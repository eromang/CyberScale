"""Views for entity registration, assessment workflow, and PDF export."""

import json

from django.contrib import messages
from django.contrib.auth import login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .assessment import run_entity_assessment, run_multi_entity_assessment
from .forms import (
    AssessmentStep1Form,
    AssessmentStep2Form,
    AssessmentStep3Form,
    RegistrationForm,
    SECTORS_WITH_SPECIFIC_FIELDS,
    _entity_types_by_sector,
)
from .models import Assessment, Entity, EntityType, Submission


def _get_entity_or_redirect(request):
    """Get the Entity for the current user, or None if not registered."""
    try:
        return Entity.objects.get(user=request.user)
    except Entity.DoesNotExist:
        return None


def register_view(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            entity = Entity.objects.create(
                user=user,
                organisation_name=form.cleaned_data["organisation_name"],
                sector=form.cleaned_data["sector"],
                entity_type=form.cleaned_data["entity_type"],
                ms_established=form.cleaned_data["ms_established"],
            )
            EntityType.objects.create(
                entity=entity,
                sector=form.cleaned_data["sector"],
                entity_type=form.cleaned_data["entity_type"],
            )
            login(request, user)
            return redirect("dashboard")
    else:
        form = RegistrationForm()
    return render(request, "entity/register.html", {
        "form": form,
        "entity_types_by_sector": _entity_types_by_sector(),
    })


def login_view(request):
    from django.contrib.auth.forms import AuthenticationForm
    from django.contrib.auth import authenticate, login as auth_login

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            return redirect("dashboard")
    else:
        form = AuthenticationForm()
    return render(request, "entity/login.html", {"form": form})


def logout_view(request):
    auth_logout(request)
    return redirect("login")


@login_required
def dashboard_view(request):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessments = entity.assessments.all()[:20]
    from .forms import _sector_choices
    return render(request, "entity/dashboard.html", {
        "entity": entity,
        "assessments": assessments,
        "sector_choices": _sector_choices(),
    })


@login_required
def assessment_form_view(request, draft_pk=None):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")

    registered_types = list(entity.entity_types.all())

    draft = None
    if draft_pk:
        draft = get_object_or_404(Assessment, pk=draft_pk, entity=entity, status="draft")

    if request.method == "POST":
        form1 = AssessmentStep1Form(request.POST, entity_types=registered_types)
        form2 = AssessmentStep2Form(request.POST)
        form3 = AssessmentStep3Form(request.POST)

        is_draft = "save_draft" in request.POST

        if form1.is_valid() and form2.is_valid() and form3.is_valid():
            sector_specific = form3.get_sector_specific()
            ms_affected = form1.cleaned_data.get("ms_affected", [])

            # Parse selected entity types
            selected_types = []
            for val in form1.cleaned_data["affected_entity_types"]:
                sector, etype = val.split(":", 1)
                selected_types.append({"sector": sector, "entity_type": etype})

            primary = selected_types[0]

            fields = dict(
                description=form1.cleaned_data["description"],
                sector=primary["sector"],
                entity_type=primary["entity_type"],
                ms_affected=ms_affected,
                affected_entity_types=selected_types,
                service_impact=form2.cleaned_data["service_impact"],
                data_impact=form2.cleaned_data["data_impact"],
                safety_impact=form2.cleaned_data["safety_impact"],
                financial_impact=form2.cleaned_data["financial_impact"],
                affected_persons_count=form2.cleaned_data["affected_persons_count"],
                impact_duration_hours=form2.cleaned_data["impact_duration_hours"],
                suspected_malicious=form2.cleaned_data["suspected_malicious"],
                physical_access_breach=form2.cleaned_data["physical_access_breach"],
                sector_specific=sector_specific,
            )

            if is_draft:
                if draft:
                    for k, v in fields.items():
                        setattr(draft, k, v)
                    draft.save()
                    assessment = draft
                else:
                    assessment = Assessment.objects.create(
                        entity=entity, status="draft", **fields,
                    )
                messages.success(request, f"Draft #{assessment.pk} saved.")
                return redirect("dashboard")
            else:
                multi_result = run_multi_entity_assessment(
                    description=fields["description"],
                    affected_entity_types=selected_types,
                    ms_established=entity.ms_established,
                    ms_affected=ms_affected or None,
                    service_impact=fields["service_impact"],
                    data_impact=fields["data_impact"],
                    financial_impact=fields["financial_impact"],
                    safety_impact=fields["safety_impact"],
                    affected_persons_count=fields["affected_persons_count"],
                    suspected_malicious=fields["suspected_malicious"],
                    impact_duration_hours=fields["impact_duration_hours"],
                    sector_specific=sector_specific or None,
                )

                result_fields = dict(
                    status="completed",
                    assessment_results=multi_result["per_type_results"],
                    result_significance=multi_result["overall_significance"],
                    result_significance_label=multi_result["overall_significance_label"],
                    result_early_warning=multi_result["overall_early_warning"],
                    result_model=multi_result["per_type_results"][0]["model"] if multi_result["per_type_results"] else "",
                    result_criteria=multi_result["per_type_results"][0]["triggered_criteria"] if multi_result["per_type_results"] else [],
                    result_framework=multi_result["per_type_results"][0]["framework"] if multi_result["per_type_results"] else "",
                    result_competent_authority=multi_result["per_type_results"][0]["competent_authority"] if multi_result["per_type_results"] else "",
                    result_raw=multi_result,
                )

                if draft:
                    for k, v in {**fields, **result_fields}.items():
                        setattr(draft, k, v)
                    draft.save()
                    return redirect("assessment_result", pk=draft.pk)
                else:
                    assessment = Assessment.objects.create(
                        entity=entity, **fields, **result_fields,
                    )
                    return redirect("assessment_result", pk=assessment.pk)
    else:
        if draft:
            initial_types = [
                f"{t['sector']}:{t['entity_type']}"
                for t in (draft.affected_entity_types or [])
            ]
            form1 = AssessmentStep1Form(
                entity_types=registered_types,
                initial={
                    "description": draft.description,
                    "affected_entity_types": initial_types,
                    "ms_affected": draft.ms_affected,
                },
            )
            form2 = AssessmentStep2Form(initial={
                "service_impact": draft.service_impact,
                "data_impact": draft.data_impact,
                "safety_impact": draft.safety_impact,
                "financial_impact": draft.financial_impact,
                "affected_persons_count": draft.affected_persons_count,
                "impact_duration_hours": draft.impact_duration_hours,
                "suspected_malicious": draft.suspected_malicious,
                "physical_access_breach": draft.physical_access_breach,
            })
            form3 = AssessmentStep3Form(initial=draft.sector_specific)
        else:
            form1 = AssessmentStep1Form(entity_types=registered_types)
            form2 = AssessmentStep2Form()
            form3 = AssessmentStep3Form()

    return render(request, "entity/assessment_form.html", {
        "entity": entity,
        "form1": form1,
        "form2": form2,
        "form3": form3,
        "draft": draft,
        "registered_types": registered_types,
    })


@login_required
def delete_draft_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    draft = get_object_or_404(Assessment, pk=pk, entity=entity, status="draft")
    if request.method == "POST":
        draft.delete()
        from django.contrib import messages
        messages.success(request, "Draft deleted.")
    return redirect("dashboard")


@login_required
def assessment_result_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)
    return render(request, "entity/assessment_result.html", {
        "entity": entity,
        "assessment": assessment,
    })


@login_required
def assessment_pdf_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    from django.template.loader import render_to_string
    html = render_to_string("entity/assessment_pdf.html", {
        "entity": entity,
        "assessment": assessment,
    })

    from weasyprint import HTML
    pdf = HTML(string=html).write_pdf()

    # Record submission
    Submission.objects.create(
        assessment=assessment, target="pdf_download", status="success"
    )
    assessment.pdf_generated_at = timezone.now()
    assessment.save(update_fields=["pdf_generated_at"])

    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="cyberscale-assessment-{assessment.pk}.pdf"'
    return response


@login_required
def assessment_misp_json_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    from .misp_export import build_misp_event, build_misp_event_for_type, build_misp_event_global
    import uuid as uuid_mod

    # Ensure UUID exists
    if not assessment.misp_event_uuid:
        assessment.misp_event_uuid = str(uuid_mod.uuid4())
        assessment.save(update_fields=["misp_event_uuid"])

    type_index = request.GET.get("type_index")

    if type_index is not None and assessment.assessment_results:
        # Per-type export
        idx = int(type_index)
        if 0 <= idx < len(assessment.assessment_results):
            type_result = assessment.assessment_results[idx]
            event = build_misp_event_for_type(assessment, entity, type_result)
            sector = type_result.get("sector", "unknown")
            filename = f"cyberscale-assessment-{assessment.pk}-{sector}.misp.json"
        else:
            event = build_misp_event_global(assessment, entity)
            filename = f"cyberscale-assessment-{assessment.pk}.misp.json"
    elif assessment.assessment_results:
        # Global export — one event with all entity type objects
        event = build_misp_event_global(assessment, entity)
        filename = f"cyberscale-assessment-{assessment.pk}.misp.json"
    else:
        # Legacy single-type export
        event = build_misp_event(assessment, entity)
        filename = f"cyberscale-assessment-{assessment.pk}.misp.json"

    json_bytes = json.dumps(event, indent=2, ensure_ascii=False).encode("utf-8")

    Submission.objects.create(
        assessment=assessment, target="misp_json_download", status="success"
    )

    response = HttpResponse(json_bytes, content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def entity_types_for_sector(request):
    """HTMX endpoint: return <option> tags for entity types filtered by sector."""
    sector = request.GET.get("sector", "")
    by_sector = _entity_types_by_sector()
    types = by_sector.get(sector, [])
    html = '<option value="">— Select entity type —</option>'
    for et in types:
        html += f'<option value="{et["id"]}">{et["label"]}</option>'
    return HttpResponse(html)


@login_required
@require_POST
def add_entity_type_view(request):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    sector = request.POST.get("sector", "")
    etype = request.POST.get("entity_type", "")
    if sector and etype:
        EntityType.objects.get_or_create(
            entity=entity, entity_type=etype, defaults={"sector": sector}
        )
    if request.headers.get("HX-Request"):
        types = entity.entity_types.all()
        return render(request, "entity/partials/entity_types.html", {"entity_types": types})
    return redirect("dashboard")


@login_required
@require_POST
def remove_entity_type_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    et = get_object_or_404(EntityType, pk=pk, entity=entity)
    if entity.entity_types.count() > 1:
        et.delete()
    else:
        messages.error(request, "Cannot remove the last entity type.")
    if request.headers.get("HX-Request"):
        types = entity.entity_types.all()
        return render(request, "entity/partials/entity_types.html", {"entity_types": types})
    return redirect("dashboard")


def sector_fields_view(request):
    """HTMX endpoint: return sector-specific fields for selected entity types."""
    sectors_param = request.GET.get("sectors", "")
    selected_sectors = set(sectors_param.split(",")) if sectors_param else set()
    relevant = selected_sectors & SECTORS_WITH_SPECIFIC_FIELDS
    if not relevant:
        return HttpResponse("")
    return render(request, "entity/partials/sector_fields.html", {"sectors": relevant})
