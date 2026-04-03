# Per-Entity-Type Impact Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the assessment form so each entity type has its own impact fields, MS affected, and sector-specific data, while keeping description and suspected malicious as global incident-level fields.

**Architecture:** New `per_type_impacts` JSONField on Assessment stores per-type impact data. The form's Step 1 gets global fields (description, entity types, malicious). Step 2 becomes HTMX-driven per-type impact fieldsets. Step 3 (sector-specific) is absorbed into Step 2. The assessment engine receives per-type impacts. MISP exports use per-type impact values.

**Tech Stack:** Django 5.x, HTMX 2.x, CyberScale core library

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `entity/models.py` | Modify | Add `per_type_impacts` JSONField to Assessment |
| `entity/migrations/` | Create | Schema + data migration |
| `entity/forms.py` | Modify | Move malicious/breach to Step1, remove Step2/Step3 forms |
| `entity/views.py` | Modify | New HTMX endpoint, rewrite assessment_form_view POST parsing |
| `entity/urls.py` | Modify | Replace sector-fields with impact-fields URL |
| `entity/assessment.py` | Modify | Update `run_multi_entity_assessment()` for per-type impacts |
| `entity/misp_export.py` | Modify | Per-type impact values in MISP objects |
| `templates/entity/assessment_form.html` | Rewrite | 3-step form, per-type impact via HTMX |
| `templates/entity/partials/impact_fields.html` | Create | HTMX partial for per-type impact fieldsets |
| `templates/entity/partials/sector_fields.html` | Remove | Absorbed into impact_fields.html |
| `templates/entity/assessment_result.html` | Modify | Per-type impact display |
| `templates/entity/assessment_pdf.html` | Modify | Per-type impact sections |

---

### Task 1: Add per_type_impacts Field + Migration

**Files:**
- Modify: `entity/models.py`
- Create: migration (auto-generated)

- [ ] **Step 1: Add `per_type_impacts` to Assessment model**

In `entity/models.py`, in the Assessment class, after the `assessment_results` field, add:

```python
    per_type_impacts = models.JSONField(
        default=list, blank=True,
        help_text="Per-entity-type impact data (ms_affected, impacts, sector_specific per type)",
    )
```

- [ ] **Step 2: Generate and run migration**

```bash
docker compose exec cyberscale-web python manage.py makemigrations entity -n per_type_impacts
docker compose exec cyberscale-web python manage.py migrate
```

- [ ] **Step 3: Data migration for existing assessments**

```bash
docker compose exec cyberscale-web python manage.py makemigrations entity --empty -n backfill_per_type_impacts
```

Replace the generated file contents with:

```python
from django.db import migrations


def backfill(apps, schema_editor):
    Assessment = apps.get_model("entity", "Assessment")
    for a in Assessment.objects.all():
        if a.affected_entity_types and not a.per_type_impacts:
            a.per_type_impacts = [
                {
                    "sector": t["sector"],
                    "entity_type": t["entity_type"],
                    "ms_affected": a.ms_affected or [],
                    "service_impact": a.service_impact,
                    "data_impact": a.data_impact,
                    "safety_impact": a.safety_impact,
                    "financial_impact": a.financial_impact,
                    "affected_persons_count": a.affected_persons_count,
                    "impact_duration_hours": a.impact_duration_hours,
                    "sector_specific": a.sector_specific or {},
                }
                for t in a.affected_entity_types
            ]
            a.save()


class Migration(migrations.Migration):
    dependencies = [
        ("entity", "0004_per_type_impacts"),
    ]
    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
```

Run: `docker compose exec cyberscale-web python manage.py migrate`

- [ ] **Step 4: Commit**

```bash
git add entity/models.py entity/migrations/
git commit -m "feat: add per_type_impacts field with backfill migration"
```

---

### Task 2: Update Forms — Global Fields in Step 1, Remove Step2/Step3

**Files:**
- Modify: `entity/forms.py`

- [ ] **Step 1: Move suspected_malicious and physical_access_breach to AssessmentStep1Form**

In `entity/forms.py`, add these two fields to the `AssessmentStep1Form` class, after `ms_affected` but before `__init__`:

```python
    suspected_malicious = forms.BooleanField(required=False, label="Suspected malicious")
    physical_access_breach = forms.BooleanField(required=False, label="Physical access breach (IR only)")
```

Remove `ms_affected` from `AssessmentStep1Form` — it moves to per-type fields.

The updated `AssessmentStep1Form` should be:

```python
class AssessmentStep1Form(forms.Form):
    """Step 1 — Incident context (global fields)."""

    description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Describe the incident..."}),
    )
    affected_entity_types = forms.MultipleChoiceField(
        choices=[],
        widget=forms.CheckboxSelectMultiple,
        help_text="Select all entity types affected by this incident.",
    )
    suspected_malicious = forms.BooleanField(required=False, label="Suspected malicious")
    physical_access_breach = forms.BooleanField(required=False, label="Physical access breach (IR only)")

    def __init__(self, *args, entity_types=None, **kwargs):
        super().__init__(*args, **kwargs)
        if entity_types:
            self.fields["affected_entity_types"].choices = [
                (
                    f"{et.sector}:{et.entity_type}",
                    f"{et.sector_label} / {et.label}",
                )
                for et in entity_types
            ]
            if len(entity_types) == 1:
                et = entity_types[0]
                self.fields["affected_entity_types"].initial = [
                    f"{et.sector}:{et.entity_type}"
                ]
```

Keep `AssessmentStep2Form` and `AssessmentStep3Form` in the file for now (they won't be used by views, but removing imports cleanly is done in Task 4).

- [ ] **Step 2: Commit**

```bash
git add entity/forms.py
git commit -m "feat: move global fields to Step1Form, per-type impacts will be HTMX-rendered"
```

---

### Task 3: Update Assessment Engine for Per-Type Impacts

**Files:**
- Modify: `entity/assessment.py`

- [ ] **Step 1: Replace `run_multi_entity_assessment()` with per-type impact version**

Replace the entire `run_multi_entity_assessment` function (lines 213-306) in `entity/assessment.py` with:

```python
def run_multi_entity_assessment(
    description: str,
    per_type_impacts: list[dict],
    ms_established: str = "EU",
    suspected_malicious: bool = False,
) -> dict:
    """Run the assessment engine for each affected entity type with per-type impacts.

    Args:
        per_type_impacts: list of dicts, each containing:
            sector, entity_type, ms_affected, service_impact, data_impact,
            safety_impact, financial_impact, affected_persons_count,
            impact_duration_hours, sector_specific

    Returns dict with:
        - per_type_results: list of per-type result dicts (includes impact data)
        - overall_significance: most severe significance across all types
        - overall_significance_label: label for the most severe
        - overall_early_warning: recommended if any type recommends it
    """
    per_type_results = []
    significance_priority = {
        "SIGNIFICANT": 6, "LIKELY": 5, "UNDETERMINED": 4,
        "UNCERTAIN": 3, "NOT SIGNIFICANT": 2, "UNLIKELY": 1, "": 0,
    }

    for impact in per_type_impacts:
        ms_affected = impact.get("ms_affected") or []
        result = run_entity_assessment(
            description=description,
            sector=impact["sector"],
            entity_type=impact["entity_type"],
            ms_established=ms_established,
            ms_affected=ms_affected or None,
            service_impact=impact.get("service_impact", "none"),
            data_impact=impact.get("data_impact", "none"),
            financial_impact=impact.get("financial_impact", "none"),
            safety_impact=impact.get("safety_impact", "none"),
            affected_persons_count=impact.get("affected_persons_count", 0),
            suspected_malicious=suspected_malicious,
            impact_duration_hours=impact.get("impact_duration_hours", 0),
            sector_specific=impact.get("sector_specific") or None,
        )

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

        per_type_results.append({
            "sector": impact["sector"],
            "entity_type": impact["entity_type"],
            "ms_affected": ms_affected,
            "service_impact": impact.get("service_impact", "none"),
            "data_impact": impact.get("data_impact", "none"),
            "safety_impact": impact.get("safety_impact", "none"),
            "financial_impact": impact.get("financial_impact", "none"),
            "affected_persons_count": impact.get("affected_persons_count", 0),
            "impact_duration_hours": impact.get("impact_duration_hours", 0),
            "significant_incident": sig_bool,
            "significance_label": sig_label,
            "model": result.get("model", ""),
            "triggered_criteria": sig_data.get("triggered_criteria", []),
            "framework": result.get("framework", ""),
            "competent_authority": result.get("competent_authority", ""),
            "early_warning": result.get("early_warning", {}),
        })

    # Determine overall significance (most severe)
    overall_label = ""
    overall_bool = None
    for r in per_type_results:
        if significance_priority.get(r["significance_label"], 0) > significance_priority.get(overall_label, 0):
            overall_label = r["significance_label"]
            overall_bool = r["significant_incident"]

    # Determine overall early warning (recommended if any type recommends)
    overall_ew = {"recommended": False, "deadline": "", "required_content": [], "next_step": ""}
    for r in per_type_results:
        ew = r.get("early_warning", {})
        if ew.get("recommended"):
            overall_ew = ew
            break

    return {
        "per_type_results": per_type_results,
        "overall_significance": overall_bool,
        "overall_significance_label": overall_label,
        "overall_early_warning": overall_ew,
    }
```

- [ ] **Step 2: Verify import**

```bash
docker compose exec cyberscale-web python -c "
import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberscale_web.settings'
django.setup()
from entity.assessment import run_multi_entity_assessment
import inspect
sig = inspect.signature(run_multi_entity_assessment)
print('Params:', list(sig.parameters.keys()))
"
```
Expected: `Params: ['description', 'per_type_impacts', 'ms_established', 'suspected_malicious']`

- [ ] **Step 3: Commit**

```bash
git add entity/assessment.py
git commit -m "feat: run_multi_entity_assessment accepts per-type impacts"
```

---

### Task 4: HTMX Impact Fields Partial + Endpoint

**Files:**
- Create: `templates/entity/partials/impact_fields.html`
- Remove: `templates/entity/partials/sector_fields.html`
- Modify: `entity/views.py`
- Modify: `entity/urls.py`

- [ ] **Step 1: Create `templates/entity/partials/impact_fields.html`**

```html
{% load entity_tags %}
{% for type_info in types %}
<fieldset>
  <legend>Impact — {{ type_info.sector_label }} / {{ type_info.label }}</legend>
  <input type="hidden" name="impact_{{ forloop.counter0 }}_type" value="{{ type_info.sector }}:{{ type_info.entity_type }}">

  <label>Member states affected
    <select name="impact_{{ forloop.counter0 }}_ms_affected" multiple size="4">
      <option value="AT">Austria</option><option value="BE">Belgium</option>
      <option value="BG">Bulgaria</option><option value="CY">Cyprus</option>
      <option value="CZ">Czechia</option><option value="DE">Germany</option>
      <option value="DK">Denmark</option><option value="EE">Estonia</option>
      <option value="ES">Spain</option><option value="FI">Finland</option>
      <option value="FR">France</option><option value="GR">Greece</option>
      <option value="HR">Croatia</option><option value="HU">Hungary</option>
      <option value="IE">Ireland</option><option value="IT">Italy</option>
      <option value="LT">Lithuania</option><option value="LU" selected>Luxembourg</option>
      <option value="LV">Latvia</option><option value="MT">Malta</option>
      <option value="NL">Netherlands</option><option value="PL">Poland</option>
      <option value="PT">Portugal</option><option value="RO">Romania</option>
      <option value="SE">Sweden</option><option value="SI">Slovenia</option>
      <option value="SK">Slovakia</option>
    </select>
  </label>

  <div class="grid">
    <label>Service impact
      <select name="impact_{{ forloop.counter0 }}_service_impact">
        <option value="none">None</option><option value="partial">Partial degradation</option>
        <option value="degraded">Degraded</option><option value="unavailable">Unavailable</option>
        <option value="sustained">Sustained unavailability</option>
      </select>
    </label>
    <label>Data impact
      <select name="impact_{{ forloop.counter0 }}_data_impact">
        <option value="none">None</option><option value="accessed">Accessed</option>
        <option value="exfiltrated">Exfiltrated</option><option value="compromised">Compromised</option>
        <option value="systemic">Systemic</option>
      </select>
    </label>
  </div>
  <div class="grid">
    <label>Safety impact
      <select name="impact_{{ forloop.counter0 }}_safety_impact">
        <option value="none">None</option><option value="health_risk">Health risk</option>
        <option value="health_damage">Health damage</option><option value="death">Death</option>
      </select>
    </label>
    <label>Financial impact
      <select name="impact_{{ forloop.counter0 }}_financial_impact">
        <option value="none">None</option><option value="minor">Minor</option>
        <option value="significant">Significant</option><option value="severe">Severe</option>
      </select>
    </label>
  </div>
  <div class="grid">
    <label>Affected persons count <input type="number" name="impact_{{ forloop.counter0 }}_affected_persons_count" min="0" value="0"></label>
    <label>Impact duration (hours) <input type="number" name="impact_{{ forloop.counter0 }}_impact_duration_hours" min="0" value="0"></label>
  </div>

  {% if type_info.sector == "energy" %}
  <details open>
    <summary style="font-size: 0.85rem;">Sector-specific: Electricity (LU)</summary>
    <div class="grid">
      <label>PODs affected <input type="number" name="impact_{{ forloop.counter0 }}_pods_affected" min="0" value=""></label>
      <label>Voltage level
        <select name="impact_{{ forloop.counter0 }}_voltage_level">
          <option value="">—</option><option value="lv">Low voltage</option>
          <option value="mv">Medium voltage</option><option value="hv_ehv">HV/EHV</option>
        </select>
      </label>
      <label>SCADA unavailable (min) <input type="number" name="impact_{{ forloop.counter0 }}_scada_unavailable_min" min="0" value=""></label>
    </div>
  </details>
  {% endif %}

  {% if type_info.sector == "transport" %}
  <details open>
    <summary style="font-size: 0.85rem;">Sector-specific: Rail (LU)</summary>
    <div class="grid">
      <label>Trains cancelled % <input type="number" name="impact_{{ forloop.counter0 }}_trains_cancelled_pct" min="0" max="100" step="0.1" value=""></label>
      <label>Slots impacted <input type="number" name="impact_{{ forloop.counter0 }}_slots_impacted" min="0" value=""></label>
    </div>
  </details>
  {% endif %}

  {% if type_info.sector == "health" %}
  <details open>
    <summary style="font-size: 0.85rem;">Sector-specific: Health (LU)</summary>
    <div class="grid">
      <label>Persons with health impact <input type="number" name="impact_{{ forloop.counter0 }}_persons_health_impact" min="0" value=""></label>
      <label>Analyses affected % <input type="number" name="impact_{{ forloop.counter0 }}_analyses_affected_pct" min="0" max="100" step="0.1" value=""></label>
    </div>
  </details>
  {% endif %}
</fieldset>
{% endfor %}
```

- [ ] **Step 2: Create template tag for entity type labels**

Create `entity/templatetags/entity_tags.py`:

```python
from django import template

register = template.Library()
```

(The partial uses `type_info.sector_label` and `type_info.label` which are properties on the objects passed from the view, not template tags. The `{% load entity_tags %}` line can be removed from the partial if not needed — but keep the templatetags module for future use.)

Actually, remove `{% load entity_tags %}` from the partial since we pass pre-built objects from the view.

- [ ] **Step 3: Add impact_fields HTMX endpoint to views.py**

Replace the `sector_fields_view` function in `entity/views.py` with:

```python
def impact_fields_view(request):
    """HTMX endpoint: return per-type impact fieldsets for selected entity types."""
    types_param = request.GET.get("types", "")
    if not types_param:
        return HttpResponse("")

    from .forms import entity_type_label, SECTORS_WITH_SPECIFIC_FIELDS

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

    return render(request, "entity/partials/impact_fields.html", {"types": types})
```

- [ ] **Step 4: Update entity/urls.py**

Replace the `htmx/sector-fields/` line with:

```python
    path("htmx/impact-fields/", views.impact_fields_view, name="htmx_impact_fields"),
```

- [ ] **Step 5: Remove `templates/entity/partials/sector_fields.html`**

```bash
rm templates/entity/partials/sector_fields.html
```

- [ ] **Step 6: Commit**

```bash
git add entity/views.py entity/urls.py templates/entity/partials/
git commit -m "feat: HTMX per-type impact fieldsets endpoint and partial"
```

---

### Task 5: Rewrite Assessment Form View (POST parsing)

**Files:**
- Modify: `entity/views.py`

- [ ] **Step 1: Update imports**

Replace the imports block (lines 1-22) with:

```python
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
```

- [ ] **Step 2: Add helper to parse per-type impacts from POST**

Add after `_get_entity_or_redirect`:

```python
def _parse_per_type_impacts(post_data) -> list[dict]:
    """Parse indexed per-type impact fields from POST data.

    Fields are named impact_0_service_impact, impact_0_data_impact, etc.
    impact_N_type contains "sector:entity_type".
    """
    impacts = []
    idx = 0
    while f"impact_{idx}_type" in post_data:
        type_val = post_data.get(f"impact_{idx}_type", "")
        if ":" not in type_val:
            idx += 1
            continue
        sector, etype = type_val.split(":", 1)

        # Collect sector-specific fields
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
```

- [ ] **Step 3: Replace `assessment_form_view` entirely**

Replace the entire function (lines 94-230) with:

```python
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

        # Parse per-type impacts from indexed POST fields
        per_type_impacts = _parse_per_type_impacts(request.POST)

        if form1.is_valid() and per_type_impacts:
            selected_types = [
                {"sector": imp["sector"], "entity_type": imp["entity_type"]}
                for imp in per_type_impacts
            ]
            primary = selected_types[0]

            # Most severe impact for backward compat flat fields
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
                multi_result = run_multi_entity_assessment(
                    description=fields["description"],
                    per_type_impacts=per_type_impacts,
                    ms_established=entity.ms_established,
                    suspected_malicious=fields["suspected_malicious"],
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

    return render(request, "entity/assessment_form.html", {
        "entity": entity,
        "form1": form1,
        "draft": draft,
        "registered_types": registered_types,
    })
```

- [ ] **Step 4: Commit**

```bash
git add entity/views.py
git commit -m "feat: assessment form view parses per-type impacts from POST"
```

---

### Task 6: Rewrite Assessment Form Template

**Files:**
- Rewrite: `templates/entity/assessment_form.html`

- [ ] **Step 1: Replace the template**

```html
{% extends "base.html" %}
{% block title %}{% if draft %}Resume Draft #{{ draft.pk }}{% else %}New Assessment{% endif %} — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>{% if draft %}Resume Draft #{{ draft.pk }}{% else %}Incident Assessment{% endif %}</h2>
  <p>{{ entity.organisation_name }} — {{ entity.ms_established }}</p>
</div>

<ul class="cs-steps">
  <li class="cs-step active"><span class="cs-step-num">1</span> Context</li>
  <li class="cs-step active"><span class="cs-step-num">2</span> Impact</li>
  <li class="cs-step"><span class="cs-step-num">3</span> Result</li>
</ul>

<form method="post">
  {% csrf_token %}

  <fieldset>
    <legend>Step 1 — Incident Context</legend>

    <label>Incident description
      {{ form1.description }}
    </label>
    {% if form1.description.errors %}<small style="color: var(--cs-significant);">{{ form1.description.errors.0 }}</small>{% endif %}

    <label style="font-weight: 600;">Affected entity types</label>
    {% if registered_types|length == 1 %}
      <p style="color: var(--cs-text-muted);">
        {{ registered_types.0.sector_label }} / {{ registered_types.0.label }}
        <input type="hidden" name="affected_entity_types" value="{{ registered_types.0.sector }}:{{ registered_types.0.entity_type }}">
      </p>
    {% else %}
      <div id="entity-type-checkboxes"
           hx-get="{% url 'htmx_impact_fields' %}"
           hx-target="#per-type-impacts"
           hx-trigger="change"
           hx-vals='js:{"types": Array.from(document.querySelectorAll("[name=affected_entity_types]:checked")).map(e => e.value).join(",")}'>
        {{ form1.affected_entity_types }}
      </div>
    {% endif %}
    {% if form1.affected_entity_types.errors %}<small style="color: var(--cs-significant);">{{ form1.affected_entity_types.errors.0 }}</small>{% endif %}

    <div class="grid">
      <label>{{ form1.suspected_malicious }} Suspected malicious</label>
      <label>{{ form1.physical_access_breach }} Physical access breach (IR only)</label>
    </div>
  </fieldset>

  <div id="per-type-impacts">
    {# Populated by HTMX when entity type checkboxes change #}
    {# Or pre-rendered for single entity type #}
    {% if registered_types|length == 1 %}
      {% include "entity/partials/impact_fields.html" with types=registered_types_dicts %}
    {% endif %}
  </div>

  <div class="cs-actions">
    <button type="submit" name="run_assessment">Run Assessment</button>
    <button type="submit" name="save_draft" class="secondary">Save Draft</button>
  </div>
</form>
{% endblock %}
```

- [ ] **Step 2: Update view to pass `registered_types_dicts` for single-type pre-render**

In the `assessment_form_view` return statement, add `registered_types_dicts`:

```python
    # Build dicts for template partial pre-rendering (single type fast path)
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
```

- [ ] **Step 3: Commit**

```bash
git add templates/entity/assessment_form.html entity/views.py
git commit -m "feat: 3-step assessment form with per-type impact fieldsets"
```

---

### Task 7: Update MISP Export for Per-Type Impacts

**Files:**
- Modify: `entity/misp_export.py`

- [ ] **Step 1: Update `build_misp_event_for_type` and `build_misp_event_global` to use per-type impacts**

In `build_misp_event_for_type`, replace the impact attribute lines (lines 109-115) with per-type impact values from `type_result`:

```python
        _attr("service-impact", "text", type_result.get("service_impact", assessment.service_impact)),
        _attr("data-impact", "text", type_result.get("data_impact", assessment.data_impact)),
        _attr("safety-impact", "text", type_result.get("safety_impact", assessment.safety_impact)),
        _attr("financial-impact", "text", type_result.get("financial_impact", assessment.financial_impact)),
        _attr("affected-persons-count", "counter", str(type_result.get("affected_persons_count", assessment.affected_persons_count))),
        _attr("impact-duration-hours", "counter", str(type_result.get("impact_duration_hours", assessment.impact_duration_hours))),
```

Add MS affected attribute (after ms-established):
```python
        _attr("ms-affected", "text", ", ".join(type_result.get("ms_affected", []))),
```

Apply the same changes to `build_misp_event_global` — replace the impact lines in the `for r in ...` loop (lines 188-193):

```python
            _attr("service-impact", "text", r.get("service_impact", assessment.service_impact)),
            _attr("data-impact", "text", r.get("data_impact", assessment.data_impact)),
            _attr("safety-impact", "text", r.get("safety_impact", assessment.safety_impact)),
            _attr("financial-impact", "text", r.get("financial_impact", assessment.financial_impact)),
            _attr("affected-persons-count", "counter", str(r.get("affected_persons_count", assessment.affected_persons_count))),
            _attr("impact-duration-hours", "counter", str(r.get("impact_duration_hours", assessment.impact_duration_hours))),
```

Add MS affected attribute in the global export too:
```python
            _attr("ms-affected", "text", ", ".join(r.get("ms_affected", []))),
```

- [ ] **Step 2: Commit**

```bash
git add entity/misp_export.py
git commit -m "feat: MISP exports use per-type impact values and MS affected"
```

---

### Task 8: Update Result Page + PDF for Per-Type Impacts

**Files:**
- Modify: `templates/entity/assessment_result.html`
- Modify: `templates/entity/assessment_pdf.html`

- [ ] **Step 1: Update result page impact summary**

In `templates/entity/assessment_result.html`, replace the Impact Summary card (lines 91-104) with per-type impact display:

```html
{# Per-type impact summaries #}
{% for r in assessment.assessment_results %}
<div class="cs-card">
  <h3>Impact — {{ r.sector|default:""|title }} / {{ r.entity_type|default:"" }}</h3>
  {% if r.ms_affected %}<p><strong>MS affected:</strong> {{ r.ms_affected|join:", " }}</p>{% endif %}
  <table>
    <tbody>
      <tr><td><strong>Service</strong></td><td>{{ r.service_impact|default:"none" }}{% if r.impact_duration_hours %} ({{ r.impact_duration_hours }}h){% endif %}</td></tr>
      <tr><td><strong>Data</strong></td><td>{{ r.data_impact|default:"none" }}</td></tr>
      <tr><td><strong>Safety</strong></td><td>{{ r.safety_impact|default:"none" }}</td></tr>
      <tr><td><strong>Financial</strong></td><td>{{ r.financial_impact|default:"none" }}</td></tr>
      <tr><td><strong>Affected persons</strong></td><td>{{ r.affected_persons_count|default:"0" }}</td></tr>
    </tbody>
  </table>
</div>
{% empty %}
{# Fallback for old assessments #}
<div class="cs-card">
  <h3>Impact Summary</h3>
  <table>
    <tbody>
      <tr><td><strong>Service</strong></td><td>{{ assessment.service_impact }}{% if assessment.impact_duration_hours %} ({{ assessment.impact_duration_hours }}h){% endif %}</td></tr>
      <tr><td><strong>Data</strong></td><td>{{ assessment.data_impact }}</td></tr>
      <tr><td><strong>Safety</strong></td><td>{{ assessment.safety_impact }}</td></tr>
      <tr><td><strong>Financial</strong></td><td>{{ assessment.financial_impact }}</td></tr>
      <tr><td><strong>Affected persons</strong></td><td>{{ assessment.affected_persons_count|default:"0" }}</td></tr>
    </tbody>
  </table>
</div>
{% endfor %}

{# Global fields #}
<div class="cs-card">
  <h3>Incident Details</h3>
  <p><strong>Suspected malicious:</strong> {% if assessment.suspected_malicious %}Yes{% else %}No{% endif %}</p>
  <p>{{ assessment.description }}</p>
</div>
```

- [ ] **Step 2: Update PDF impact section similarly**

In `templates/entity/assessment_pdf.html`, replace the Impact Summary section with per-type impacts. Find `<h2>Impact Summary</h2>` and replace through the end of that table with:

```html
{% if assessment.assessment_results %}
  {% for r in assessment.assessment_results %}
  <h2>Impact — {{ r.sector|default:""|title }} / {{ r.entity_type|default:"" }}</h2>
  {% if r.ms_affected %}<p style="color: #6c757d; font-size: 10pt;">MS affected: {{ r.ms_affected|join:", " }}</p>{% endif %}
  <table>
    <tr><th>Service</th><td>{{ r.service_impact|default:"none" }}{% if r.impact_duration_hours %} ({{ r.impact_duration_hours }}h){% endif %}</td></tr>
    <tr><th>Data</th><td>{{ r.data_impact|default:"none" }}</td></tr>
    <tr><th>Safety</th><td>{{ r.safety_impact|default:"none" }}</td></tr>
    <tr><th>Financial</th><td>{{ r.financial_impact|default:"none" }}</td></tr>
    <tr><th>Affected persons</th><td>{{ r.affected_persons_count|default:"0" }}</td></tr>
  </table>
  {% endfor %}
{% else %}
  <h2>Impact Summary</h2>
  <table>
    <tr><th>Service</th><td>{{ assessment.service_impact }}{% if assessment.impact_duration_hours %} ({{ assessment.impact_duration_hours }}h){% endif %}</td></tr>
    <tr><th>Data</th><td>{{ assessment.data_impact }}</td></tr>
    <tr><th>Safety</th><td>{{ assessment.safety_impact }}</td></tr>
    <tr><th>Financial</th><td>{{ assessment.financial_impact }}</td></tr>
    <tr><th>Affected persons</th><td>{{ assessment.affected_persons_count|default:"0" }}</td></tr>
    <tr><th>Suspected malicious</th><td>{% if assessment.suspected_malicious %}Yes{% else %}No{% endif %}</td></tr>
  </table>
{% endif %}
```

- [ ] **Step 3: Verify**

```bash
docker compose exec cyberscale-web python manage.py collectstatic --noinput
curl -s -c /tmp/cs_test -b /tmp/cs_test http://localhost:8000/login/ -o /dev/null -w "%{http_code}"
```

- [ ] **Step 4: Commit**

```bash
git add templates/entity/assessment_result.html templates/entity/assessment_pdf.html
git commit -m "feat: per-type impact display in result page and PDF"
```
