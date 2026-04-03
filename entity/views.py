"""Views for entity registration, assessment workflow, and PDF export."""

import json

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .assessment import run_entity_assessment
from .forms import (
    AssessmentStep1Form,
    AssessmentStep2Form,
    AssessmentStep3Form,
    RegistrationForm,
    _entity_types_by_sector,
)
from .models import Assessment, Entity, Submission


def register_view(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            Entity.objects.create(
                user=user,
                organisation_name=form.cleaned_data["organisation_name"],
                sector=form.cleaned_data["sector"],
                entity_type=form.cleaned_data["entity_type"],
                ms_established=form.cleaned_data["ms_established"],
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


@login_required
def dashboard_view(request):
    entity = get_object_or_404(Entity, user=request.user)
    assessments = entity.assessments.all()[:20]
    return render(request, "entity/dashboard.html", {
        "entity": entity,
        "assessments": assessments,
    })


@login_required
def assessment_form_view(request):
    entity = get_object_or_404(Entity, user=request.user)

    if request.method == "POST":
        form1 = AssessmentStep1Form(request.POST)
        form2 = AssessmentStep2Form(request.POST)
        form3 = AssessmentStep3Form(request.POST)

        if form1.is_valid() and form2.is_valid() and form3.is_valid():
            # Run assessment engine
            sector_specific = form3.get_sector_specific()
            ms_affected = form1.cleaned_data.get("ms_affected", [])

            result = run_entity_assessment(
                description=form1.cleaned_data["description"],
                sector=entity.sector,
                entity_type=entity.entity_type,
                ms_established=entity.ms_established,
                ms_affected=ms_affected or None,
                service_impact=form2.cleaned_data["service_impact"],
                data_impact=form2.cleaned_data["data_impact"],
                financial_impact=form2.cleaned_data["financial_impact"],
                safety_impact=form2.cleaned_data["safety_impact"],
                affected_persons_count=form2.cleaned_data["affected_persons_count"],
                suspected_malicious=form2.cleaned_data["suspected_malicious"],
                impact_duration_hours=form2.cleaned_data["impact_duration_hours"],
                sector_specific=sector_specific or None,
            )

            # Extract significance info
            sig_data = result.get("significance", {})
            significant = sig_data.get("significant_incident")
            if isinstance(significant, str):
                sig_label = significant.upper()
                sig_bool = significant == "likely"
            elif isinstance(significant, bool):
                sig_label = "SIGNIFICANT" if significant else "NOT SIGNIFICANT"
                sig_bool = significant
            else:
                sig_label = "UNDETERMINED"
                sig_bool = None

            # Save assessment
            assessment = Assessment.objects.create(
                entity=entity,
                status="completed",
                description=form1.cleaned_data["description"],
                sector=entity.sector,
                entity_type=entity.entity_type,
                ms_affected=ms_affected,
                service_impact=form2.cleaned_data["service_impact"],
                data_impact=form2.cleaned_data["data_impact"],
                safety_impact=form2.cleaned_data["safety_impact"],
                financial_impact=form2.cleaned_data["financial_impact"],
                affected_persons_count=form2.cleaned_data["affected_persons_count"],
                impact_duration_hours=form2.cleaned_data["impact_duration_hours"],
                suspected_malicious=form2.cleaned_data["suspected_malicious"],
                physical_access_breach=form2.cleaned_data["physical_access_breach"],
                sector_specific=sector_specific,
                result_significance=sig_bool,
                result_significance_label=sig_label,
                result_model=result.get("model", ""),
                result_criteria=sig_data.get("triggered_criteria", []),
                result_framework=result.get("framework", ""),
                result_competent_authority=result.get("competent_authority", ""),
                result_early_warning=result.get("early_warning", {}),
                result_raw=result,
            )

            return redirect("assessment_result", pk=assessment.pk)
    else:
        form1 = AssessmentStep1Form()
        form2 = AssessmentStep2Form()
        form3 = AssessmentStep3Form()

    return render(request, "entity/assessment_form.html", {
        "entity": entity,
        "form1": form1,
        "form2": form2,
        "form3": form3,
    })


@login_required
def assessment_result_view(request, pk):
    entity = get_object_or_404(Entity, user=request.user)
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)
    return render(request, "entity/assessment_result.html", {
        "entity": entity,
        "assessment": assessment,
    })


@login_required
def assessment_pdf_view(request, pk):
    entity = get_object_or_404(Entity, user=request.user)
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
    entity = get_object_or_404(Entity, user=request.user)
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    from .misp_export import build_misp_event
    import uuid as uuid_mod

    # Generate UUID if not set
    if not assessment.misp_event_uuid:
        assessment.misp_event_uuid = str(uuid_mod.uuid4())
        assessment.save(update_fields=["misp_event_uuid"])

    event = build_misp_event(assessment, entity)
    json_bytes = json.dumps(event, indent=2, ensure_ascii=False).encode("utf-8")

    Submission.objects.create(
        assessment=assessment, target="misp_json_download", status="success"
    )

    response = HttpResponse(json_bytes, content_type="application/json")
    response["Content-Disposition"] = (
        f'attachment; filename="cyberscale-assessment-{assessment.pk}.misp.json"'
    )
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
