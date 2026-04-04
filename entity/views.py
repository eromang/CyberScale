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
    RegistrationForm,
    SECTORS_WITH_SPECIFIC_FIELDS,
    entity_type_label,
    _entity_types_by_sector,
)
from .models import Assessment, Entity, EntityType, Submission


def _get_entity_or_redirect(request):
    """Get the Entity for the current user, or None if not registered."""
    try:
        return Entity.objects.get(user=request.user)
    except Entity.DoesNotExist:
        return None


def _parse_per_type_impacts(post_data) -> list[dict]:
    """Parse indexed per-type impact fields from POST data."""
    impacts = []
    idx = 0
    while f"impact_{idx}_type" in post_data:
        type_val = post_data.get(f"impact_{idx}_type", "")
        if ":" not in type_val:
            idx += 1
            continue
        sector, etype = type_val.split(":", 1)

        sector_specific = {}
        for ss_field in ("pods_affected", "voltage_level", "scada_unavailable_min",
                         "trains_cancelled_pct", "slots_impacted",
                         "persons_health_impact", "analyses_affected_pct"):
            val = post_data.get(f"impact_{idx}_{ss_field}", "")
            if val not in ("", None):
                try:
                    if ss_field in ("trains_cancelled_pct", "analyses_affected_pct"):
                        sector_specific[ss_field] = float(val)
                    elif ss_field == "voltage_level":
                        sector_specific[ss_field] = val
                    else:
                        sector_specific[ss_field] = int(val)
                except (ValueError, TypeError):
                    pass

        impacts.append({
            "sector": sector,
            "entity_type": etype,
            "ms_affected": post_data.getlist(f"impact_{idx}_ms_affected"),
            "service_impact": post_data.get(f"impact_{idx}_service_impact", "none"),
            "data_impact": post_data.get(f"impact_{idx}_data_impact", "none"),
            "safety_impact": post_data.get(f"impact_{idx}_safety_impact", "none"),
            "financial_impact": post_data.get(f"impact_{idx}_financial_impact", "none"),
            "affected_persons_count": int(post_data.get(f"impact_{idx}_affected_persons_count", 0) or 0),
            "impact_duration_hours": int(post_data.get(f"impact_{idx}_impact_duration_hours", 0) or 0),
            "sector_specific": sector_specific,
        })
        idx += 1
    return impacts


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
            et = EntityType.objects.create(
                entity=entity,
                sector=form.cleaned_data["sector"],
                entity_type=form.cleaned_data["entity_type"],
            )
            from .authority import assign_authority
            assign_authority(et)
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
    from django.db.models import Exists, OuterRef
    assessments = entity.assessments.annotate(
        has_early_warning=Exists(
            Submission.objects.filter(
                assessment=OuterRef("pk"), target="early_warning", status="success"
            )
        ),
    )[:20]
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
        is_draft = "save_draft" in request.POST

        per_type_impacts = _parse_per_type_impacts(request.POST)

        if form1.is_valid() and per_type_impacts:
            selected_types = [
                {"sector": imp["sector"], "entity_type": imp["entity_type"]}
                for imp in per_type_impacts
            ]
            primary = selected_types[0]

            severity_order = {"none": 0, "partial": 1, "degraded": 2, "unavailable": 3, "sustained": 4,
                              "accessed": 1, "exfiltrated": 2, "compromised": 3, "systemic": 4,
                              "health_risk": 1, "health_damage": 2, "death": 3,
                              "minor": 1, "significant": 2, "severe": 3}
            worst = max(per_type_impacts, key=lambda i: severity_order.get(i.get("service_impact", "none"), 0))

            fields = dict(
                description=form1.cleaned_data["description"],
                sector=primary["sector"],
                entity_type=primary["entity_type"],
                affected_entity_types=selected_types,
                per_type_impacts=per_type_impacts,
                ms_affected=worst.get("ms_affected", []),
                service_impact=worst.get("service_impact", "none"),
                data_impact=worst.get("data_impact", "none"),
                safety_impact=worst.get("safety_impact", "none"),
                financial_impact=worst.get("financial_impact", "none"),
                affected_persons_count=worst.get("affected_persons_count", 0),
                impact_duration_hours=worst.get("impact_duration_hours", 0),
                suspected_malicious=form1.cleaned_data["suspected_malicious"],
                physical_access_breach=form1.cleaned_data["physical_access_breach"],
                sector_specific=worst.get("sector_specific", {}),
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
                et_objs = {}
                for et in entity.entity_types.select_related("competent_authority", "csirt").all():
                    et_objs[f"{et.sector}:{et.entity_type}"] = et

                multi_result = run_multi_entity_assessment(
                    description=fields["description"],
                    per_type_impacts=per_type_impacts,
                    ms_established=entity.ms_established,
                    suspected_malicious=fields["suspected_malicious"],
                    entity_type_objs=et_objs,
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
        elif form1.is_valid() and not per_type_impacts:
            messages.error(request, "Please fill in impact fields for at least one entity type.")
    else:
        if draft:
            form1 = AssessmentStep1Form(
                entity_types=registered_types,
                initial={
                    "description": draft.description,
                    "affected_entity_types": [
                        f"{t['sector']}:{t['entity_type']}"
                        for t in (draft.affected_entity_types or [])
                    ],
                    "suspected_malicious": draft.suspected_malicious,
                    "physical_access_breach": draft.physical_access_breach,
                },
            )
        else:
            form1 = AssessmentStep1Form(entity_types=registered_types)

    registered_types_dicts = [
        {
            "sector": et.sector,
            "entity_type": et.entity_type,
            "sector_label": et.sector_label,
            "label": et.label,
        }
        for et in registered_types
    ]

    return render(request, "entity/assessment_form.html", {
        "entity": entity,
        "form1": form1,
        "draft": draft,
        "registered_types": registered_types,
        "registered_types_dicts": registered_types_dicts,
    })


@login_required
def delete_draft_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    draft = get_object_or_404(Assessment, pk=pk, entity=entity, status="draft")
    if request.method == "POST":
        draft.delete()
        messages.success(request, "Draft deleted.")
    return redirect("dashboard")


@login_required
@require_POST
def delete_assessment_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)
    if assessment.submissions.filter(target="early_warning").exists():
        messages.error(request, "Cannot delete an assessment with a submitted early warning.")
        return redirect("assessment_result", pk=pk)
    assessment.delete()
    messages.success(request, f"Assessment #{pk} deleted.")
    return redirect("dashboard")


@login_required
def assessment_result_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    ew_submitted = assessment.submissions.filter(target="early_warning", status="success").exists()
    ew_recommended = assessment.result_early_warning.get("recommended", False)

    ew_status = ""
    ew_support_requested = False
    if ew_submitted:
        import os
        from .misp_push import get_event_tags
        push_sub = assessment.submissions.filter(target="misp_push", status="success").first()
        if push_sub and push_sub.misp_event_id and entity.misp_instance_url:
            ssl = os.environ.get("MISP_SSL_VERIFY", "").lower() not in ("0", "false", "no", "")
            tags = get_event_tags(entity.misp_instance_url, entity.misp_api_key, push_sub.misp_event_id, ssl=ssl)
            for tag in tags:
                if tag.startswith("cyberscale:notification-status="):
                    ew_status = tag.split("=", 1)[1].strip('"')
                if tag == 'cyberscale:support-requested="true"':
                    ew_support_requested = True

    return render(request, "entity/assessment_result.html", {
        "entity": entity,
        "assessment": assessment,
        "ew_submitted": ew_submitted,
        "ew_recommended": ew_recommended,
        "ew_status": ew_status,
        "ew_support_requested": ew_support_requested,
    })


@login_required
def early_warning_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")

    assessment = get_object_or_404(Assessment, pk=pk, entity=entity, status="completed")

    if not assessment.result_early_warning.get("recommended"):
        from django.http import Http404
        raise Http404

    if assessment.submissions.filter(target="early_warning", status="success").exists():
        messages.info(request, "Early warning already submitted.")
        return redirect("assessment_result", pk=pk)

    from .forms import EarlyWarningForm

    if request.method == "POST":
        form = EarlyWarningForm(request.POST)
        if form.is_valid():
            from .misp_push import push_event, add_object_to_event, update_event_tags
            from .misp_export import build_misp_event_global, build_misp_event
            import os
            import uuid as uuid_mod

            deadline = "4h" if "DORA" in (assessment.result_framework or "") else "24h"
            now = timezone.now()

            misp_url = entity.misp_instance_url
            misp_key = entity.misp_api_key
            ssl = os.environ.get("MISP_SSL_VERIFY", "").lower() not in ("0", "false", "no", "")

            if not misp_url or not misp_key:
                messages.error(request, "MISP instance URL and API key must be configured.")
                return redirect("assessment_result", pk=pk)

            # Ensure assessment has a UUID
            if not assessment.misp_event_uuid:
                assessment.misp_event_uuid = str(uuid_mod.uuid4())
                assessment.save(update_fields=["misp_event_uuid"])

            # Build the assessment event with all data
            profile_uuid = entity.misp_profile_event_uuid or ""
            if assessment.assessment_results:
                event_dict = build_misp_event_global(assessment, entity, profile_event_uuid=profile_uuid)
            else:
                event_dict = build_misp_event(assessment, entity, profile_event_uuid=profile_uuid)

            # Add early warning object to the event
            ew_object = {
                "name": "cyberscale-early-warning",
                "meta-category": "misc",
                "template_uuid": "c5e0f001-e27a-4f00-a000-000000000003",
                "template_version": "1",
                "uuid": str(uuid_mod.uuid4()),
                "Attribute": [
                    {"object_relation": "submission-timestamp", "type": "datetime", "value": now.strftime("%Y-%m-%dT%H:%M:%S+0000")},
                    {"object_relation": "deadline", "type": "text", "value": deadline},
                    {"object_relation": "suspected-malicious", "type": "boolean", "value": "1" if form.cleaned_data["suspected_malicious"] else "0"},
                    {"object_relation": "cross-border-impact", "type": "boolean", "value": "1" if form.cleaned_data["cross_border_impact"] else "0"},
                    {"object_relation": "description", "type": "text", "value": form.cleaned_data["description"]},
                    {"object_relation": "support-requested", "type": "boolean", "value": "1" if form.cleaned_data["support_requested"] else "0"},
                    {"object_relation": "notification-recipient", "type": "text", "value": assessment.result_competent_authority},
                ],
            }
            if form.cleaned_data.get("support_description"):
                ew_object["Attribute"].append(
                    {"object_relation": "support-description", "type": "text", "value": form.cleaned_data["support_description"]},
                )

            # Check if assessment was already pushed to MISP
            existing_push = assessment.submissions.filter(target="misp_push", status="success").first()

            if existing_push and existing_push.misp_event_id:
                # Add early warning object to existing MISP event
                result = add_object_to_event(misp_url, misp_key, existing_push.misp_event_id, ew_object, ssl=ssl)

                if result["success"]:
                    # Add lifecycle tags to existing event
                    tags_to_add = [
                        'nis2:notification-stage="early-warning"',
                        'cyberscale:notification-status="received"',
                    ]
                    if form.cleaned_data["support_requested"]:
                        tags_to_add.append('cyberscale:support-requested="true"')
                    for tag in tags_to_add:
                        update_event_tags(misp_url, misp_key, existing_push.misp_event_id, add_tag=tag, ssl=ssl)

                    Submission.objects.create(
                        assessment=assessment, target="early_warning", status="success",
                    )
                    messages.success(request, f"Early warning submitted to MISP. Deadline: {deadline} from now.")
                else:
                    Submission.objects.create(
                        assessment=assessment, target="early_warning", status="failed",
                    )
                    messages.error(request, f"Early warning submission failed: {result['error']}")
            else:
                # No existing event — create new event with assessment + early warning
                event_dict["Event"]["Object"].append(ew_object)
                event_dict["Event"]["Tag"].append({"name": 'nis2:notification-stage="early-warning"'})
                event_dict["Event"]["Tag"].append({"name": 'cyberscale:notification-status="received"'})
                if form.cleaned_data["support_requested"]:
                    event_dict["Event"]["Tag"].append({"name": 'cyberscale:support-requested="true"'})

                result = push_event(misp_url, misp_key, event_dict, ssl=ssl)

                if result["success"]:
                    Submission.objects.create(
                        assessment=assessment, target="misp_push", status="success",
                        misp_event_id=result["event_id"] or "",
                    )
                    Submission.objects.create(
                        assessment=assessment, target="early_warning", status="success",
                    )
                    messages.success(request, f"Early warning submitted to MISP. Deadline: {deadline} from now.")
                else:
                    Submission.objects.create(
                        assessment=assessment, target="early_warning", status="failed",
                    )
                    messages.error(request, f"Early warning submission failed: {result['error']}")

            return redirect("assessment_result", pk=pk)
    else:
        form = EarlyWarningForm(initial={
            "description": assessment.description,
            "suspected_malicious": assessment.suspected_malicious,
            "cross_border_impact": any(
                ms != entity.ms_established
                for r in (assessment.assessment_results or [])
                for ms in r.get("ms_affected", [])
            ),
        })

    notification_recipient = ""
    csirt = ""
    if assessment.assessment_results:
        r = assessment.assessment_results[0]
        notification_recipient = r.get("notification_recipient", assessment.result_competent_authority)
        csirt = r.get("csirt", "")

    deadline = "4h" if "DORA" in (assessment.result_framework or "") else "24h"

    return render(request, "entity/early_warning_form.html", {
        "entity": entity,
        "assessment": assessment,
        "form": form,
        "notification_recipient": notification_recipient,
        "csirt": csirt,
        "deadline": deadline,
    })


@login_required
def profile_edit_view(request):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")

    from .forms import EntityProfileForm

    if request.method == "POST":
        form = EntityProfileForm(request.POST, instance=entity)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated.")
            return redirect("dashboard")
    else:
        form = EntityProfileForm(instance=entity)

    return render(request, "entity/profile_edit.html", {
        "entity": entity,
        "form": form,
    })


@login_required
def assessment_pdf_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    ew_submission = assessment.submissions.filter(target="early_warning", status="success").first()

    from django.template.loader import render_to_string
    html = render_to_string("entity/assessment_pdf.html", {
        "entity": entity,
        "assessment": assessment,
        "ew_submitted": ew_submission is not None,
        "ew_submission": ew_submission,
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
        et_obj, created = EntityType.objects.get_or_create(
            entity=entity, entity_type=etype, defaults={"sector": sector}
        )
        if created:
            from .authority import assign_authority
            assign_authority(et_obj)
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


def impact_fields_view(request):
    """HTMX endpoint: return per-type impact fieldsets for selected entity types."""
    types_param = request.GET.get("types", "")
    if not types_param:
        return HttpResponse("")

    from .forms import entity_type_label

    types = []
    for val in types_param.split(","):
        if ":" not in val:
            continue
        sector, etype = val.split(":", 1)
        types.append({
            "sector": sector,
            "entity_type": etype,
            "sector_label": sector.replace("_", " ").title(),
            "label": entity_type_label(etype),
        })

    if not types:
        return HttpResponse("")

    # Compute allowed MS from entity profile
    allowed_ms = []
    if request.user.is_authenticated:
        try:
            entity = Entity.objects.get(user=request.user)
            if entity.ms_services:
                allowed_ms_set = set(entity.ms_services) | {entity.ms_established}
                allowed_ms = sorted(allowed_ms_set)
        except Entity.DoesNotExist:
            pass

    return render(request, "entity/partials/impact_fields.html", {
        "types": types,
        "allowed_ms": allowed_ms,
    })
