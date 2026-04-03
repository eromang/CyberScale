# Multi-Entity-Type Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support entities with multiple sectors/entity types, run per-type assessments from a single incident form, and show unified multi-type results.

**Architecture:** New `EntityType` M2M model replaces Entity's single sector/entity_type. Assessment form gets a multi-select of affected entity types. Assessment engine runs per type, storing results in a new `assessment_results` JSON field. Result page, PDF, and MISP export render per-type cards. HTMX drives dynamic sector-specific fields and entity type management on the dashboard.

**Tech Stack:** Django 5.x, HTMX 2.x, Pico CSS, CyberScale core library

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `entity/models.py` | Modify | Add `EntityType` model, add `affected_entity_types` + `assessment_results` to Assessment |
| `entity/migrations/0002_entitytype_multi.py` | Create | Schema migration + data migration |
| `entity/forms.py` | Modify | Add `AffectedEntityTypesField`, update Step 1 form |
| `entity/assessment.py` | Modify | Add `run_multi_entity_assessment()` |
| `entity/views.py` | Modify | Update assessment flow, add entity type management views, add sector-fields HTMX endpoint |
| `entity/urls.py` | Modify | Add new URL patterns |
| `entity/admin.py` | Modify | Register `EntityType`, update `EntityAdmin` |
| `entity/misp_export.py` | Modify | Support per-type exports |
| `templates/entity/dashboard.html` | Modify | Entity types list with add/remove |
| `templates/entity/assessment_form.html` | Modify | Entity type multi-select, dynamic sector fields |
| `templates/entity/assessment_result.html` | Modify | Per-type result cards |
| `templates/entity/assessment_pdf.html` | Modify | Per-type sections |
| `templates/entity/partials/entity_types.html` | Create | HTMX partial for entity type list |
| `templates/entity/partials/sector_fields.html` | Create | HTMX partial for sector-specific fields |

---

### Task 1: EntityType Model + Migration

**Files:**
- Modify: `entity/models.py`
- Create: `entity/migrations/0002_entitytype_multi.py` (auto-generated)

- [ ] **Step 1: Add EntityType model and new Assessment fields to `entity/models.py`**

Add the `EntityType` class after the `Entity` class. Add new fields to `Assessment`. Keep `sector` and `entity_type` on `Entity` for now (removed in data migration step).

Add after the `Entity` class (after line 26):

```python
class EntityType(models.Model):
    """A sector/entity_type registration for an Entity. One Entity can have many."""

    entity = models.ForeignKey(
        "Entity", on_delete=models.CASCADE, related_name="entity_types"
    )
    sector = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=100)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("entity", "entity_type")
        ordering = ["sector", "entity_type"]

    def __str__(self):
        return f"{self.sector}/{self.entity_type}"

    @property
    def label(self):
        """Human-readable label from reference data."""
        from .forms import _load_entity_type_data
        for et in _load_entity_type_data():
            if et["id"] == self.entity_type:
                return et["label"]
        return self.entity_type.replace("_", " ").title()

    @property
    def sector_label(self):
        return self.sector.replace("_", " ").title()
```

Add these two fields to the `Assessment` model, after `sector_specific` (after line 62):

```python
    # Multi-entity-type support
    affected_entity_types = models.JSONField(
        default=list, blank=True,
        help_text='List of {"sector": "...", "entity_type": "..."} dicts',
    )
    assessment_results = models.JSONField(
        default=list, blank=True,
        help_text="Per-entity-type assessment results",
    )
```

- [ ] **Step 2: Generate migration**

```bash
docker compose exec cyberscale-web python manage.py makemigrations entity -n entitytype_multi
```

- [ ] **Step 3: Run migration**

```bash
docker compose exec cyberscale-web python manage.py migrate
```

- [ ] **Step 4: Commit**

```bash
git add entity/models.py entity/migrations/
git commit -m "feat: add EntityType model and multi-type Assessment fields"
```

---

### Task 2: Data Migration — Populate EntityType Records

**Files:**
- Create: `entity/migrations/0003_populate_entity_types.py`

- [ ] **Step 1: Create data migration**

```bash
docker compose exec cyberscale-web python manage.py makemigrations entity --empty -n populate_entity_types
```

- [ ] **Step 2: Edit the generated migration file**

Replace the contents of the generated `entity/migrations/0003_populate_entity_types.py` with:

```python
from django.db import migrations


def populate_entity_types(apps, schema_editor):
    """Create EntityType records from existing Entity sector/entity_type fields."""
    Entity = apps.get_model("entity", "Entity")
    EntityType = apps.get_model("entity", "EntityType")
    Assessment = apps.get_model("entity", "Assessment")

    for entity in Entity.objects.all():
        if entity.sector and entity.entity_type:
            EntityType.objects.get_or_create(
                entity=entity,
                entity_type=entity.entity_type,
                defaults={"sector": entity.sector},
            )

    for assessment in Assessment.objects.all():
        if assessment.sector and assessment.entity_type:
            assessment.affected_entity_types = [
                {"sector": assessment.sector, "entity_type": assessment.entity_type}
            ]
            # Populate assessment_results from existing result fields
            if assessment.status == "completed":
                assessment.assessment_results = [{
                    "sector": assessment.sector,
                    "entity_type": assessment.entity_type,
                    "significant_incident": assessment.result_significance,
                    "significance_label": assessment.result_significance_label,
                    "model": assessment.result_model,
                    "triggered_criteria": assessment.result_criteria,
                    "framework": assessment.result_framework,
                    "competent_authority": assessment.result_competent_authority,
                    "early_warning": assessment.result_early_warning,
                }]
            assessment.save()


def reverse_populate(apps, schema_editor):
    pass  # No reverse needed — Entity fields still exist


class Migration(migrations.Migration):

    dependencies = [
        ("entity", "0002_entitytype_multi"),
    ]

    operations = [
        migrations.RunPython(populate_entity_types, reverse_populate),
    ]
```

- [ ] **Step 3: Run data migration**

```bash
docker compose exec cyberscale-web python manage.py migrate
```

- [ ] **Step 4: Verify data migrated**

```bash
docker compose exec cyberscale-web python -c "
import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberscale_web.settings'
django.setup()
from entity.models import EntityType, Assessment
print(f'EntityTypes: {EntityType.objects.count()}')
for et in EntityType.objects.all():
    print(f'  {et.entity.organisation_name}: {et.sector}/{et.entity_type}')
a = Assessment.objects.filter(status='completed').first()
if a:
    print(f'Assessment #{a.pk} affected_entity_types: {a.affected_entity_types}')
    print(f'Assessment #{a.pk} assessment_results count: {len(a.assessment_results)}')
"
```

- [ ] **Step 5: Commit**

```bash
git add entity/migrations/
git commit -m "feat: data migration populates EntityType records from existing data"
```

---

### Task 3: Multi-Entity Assessment Engine

**Files:**
- Modify: `entity/assessment.py`

- [ ] **Step 1: Add `run_multi_entity_assessment()` to `entity/assessment.py`**

Add this function at the end of `entity/assessment.py`:

```python
def run_multi_entity_assessment(
    description: str,
    affected_entity_types: list[dict],
    ms_established: str = "EU",
    ms_affected: list[str] | None = None,
    service_impact: str = "none",
    data_impact: str = "none",
    financial_impact: str = "none",
    safety_impact: str = "none",
    affected_persons_count: int = 0,
    suspected_malicious: bool = False,
    impact_duration_hours: int = 0,
    sector_specific: dict | None = None,
) -> dict:
    """Run the assessment engine for each affected entity type.

    Args:
        affected_entity_types: list of {"sector": "...", "entity_type": "..."} dicts

    Returns dict with:
        - per_type_results: list of per-type result dicts
        - overall_significance: most severe significance across all types
        - overall_significance_label: label for the most severe
        - overall_early_warning: recommended if any type recommends it
    """
    per_type_results = []
    significance_priority = {
        "SIGNIFICANT": 6, "LIKELY": 5, "UNDETERMINED": 4,
        "UNCERTAIN": 3, "NOT SIGNIFICANT": 2, "UNLIKELY": 1, "": 0,
    }

    for et in affected_entity_types:
        result = run_entity_assessment(
            description=description,
            sector=et["sector"],
            entity_type=et["entity_type"],
            ms_established=ms_established,
            ms_affected=ms_affected,
            service_impact=service_impact,
            data_impact=data_impact,
            financial_impact=financial_impact,
            safety_impact=safety_impact,
            affected_persons_count=affected_persons_count,
            suspected_malicious=suspected_malicious,
            impact_duration_hours=impact_duration_hours,
            sector_specific=sector_specific,
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
            "sector": et["sector"],
            "entity_type": et["entity_type"],
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
print('OK')
"
```

- [ ] **Step 3: Commit**

```bash
git add entity/assessment.py
git commit -m "feat: add run_multi_entity_assessment for per-type assessments"
```

---

### Task 4: Update Forms — Entity Type Multi-Select

**Files:**
- Modify: `entity/forms.py`

- [ ] **Step 1: Add helper + update Step 1 form**

In `entity/forms.py`, add this helper function after `_entity_types_by_sector()` (after line 47):

```python
# Mapping of sectors that have sector-specific fields (LU thresholds)
SECTORS_WITH_SPECIFIC_FIELDS = {"energy", "transport", "health"}


def entity_type_label(entity_type_id: str) -> str:
    """Get human-readable label for an entity type ID."""
    data = _load_entity_type_data()
    for et in data:
        if et["id"] == entity_type_id:
            return et["label"]
    return entity_type_id.replace("_", " ").title()
```

Replace the `AssessmentStep1Form` class (lines 99-110) with:

```python
class AssessmentStep1Form(forms.Form):
    """Step 1 — Incident context."""

    description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "Describe the incident..."}),
    )
    affected_entity_types = forms.MultipleChoiceField(
        choices=[],
        widget=forms.CheckboxSelectMultiple,
        help_text="Select all entity types affected by this incident.",
    )
    ms_affected = forms.MultipleChoiceField(
        choices=MS_CHOICES[1:],
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 6}),
        help_text="Select all affected member states (Ctrl+click for multiple).",
    )

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
            # Auto-select if only one
            if len(entity_types) == 1:
                et = entity_types[0]
                self.fields["affected_entity_types"].initial = [
                    f"{et.sector}:{et.entity_type}"
                ]
```

- [ ] **Step 2: Commit**

```bash
git add entity/forms.py
git commit -m "feat: add entity type multi-select to assessment Step 1 form"
```

---

### Task 5: Update Views — Assessment Flow + Entity Type Management

**Files:**
- Modify: `entity/views.py`
- Modify: `entity/urls.py`

- [ ] **Step 1: Update imports in `entity/views.py`**

Replace the imports block (lines 1-19) with:

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
    AssessmentStep2Form,
    AssessmentStep3Form,
    RegistrationForm,
    SECTORS_WITH_SPECIFIC_FIELDS,
    _entity_types_by_sector,
)
from .models import Assessment, Entity, EntityType, Submission
```

- [ ] **Step 2: Update `register_view` to create EntityType**

Replace the `register_view` function (lines 30-49) with:

```python
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
```

- [ ] **Step 3: Replace `assessment_form_view` with multi-type version**

Replace the entire `assessment_form_view` function with:

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

            # Use first selected type as primary (for backward compat fields)
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
                # Run multi-entity assessment
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
                    # For backward compat, store first type's details
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
            # Reconstruct affected_entity_types selection from draft
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
```

- [ ] **Step 4: Add entity type management views**

Add these views after `entity_types_for_sector`:

```python
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
```

- [ ] **Step 5: Update `entity/urls.py`**

Replace the entire contents of `entity/urls.py`:

```python
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("assess/", views.assessment_form_view, name="assessment_form"),
    path("assess/draft/<int:draft_pk>/", views.assessment_form_view, name="resume_draft"),
    path("assess/draft/<int:pk>/delete/", views.delete_draft_view, name="delete_draft"),
    path("assess/<int:pk>/", views.assessment_result_view, name="assessment_result"),
    path("assess/<int:pk>/pdf/", views.assessment_pdf_view, name="assessment_pdf"),
    path("assess/<int:pk>/misp-json/", views.assessment_misp_json_view, name="assessment_misp_json"),
    path("htmx/entity-types/", views.entity_types_for_sector, name="htmx_entity_types"),
    path("htmx/sector-fields/", views.sector_fields_view, name="htmx_sector_fields"),
    path("entity-type/add/", views.add_entity_type_view, name="add_entity_type"),
    path("entity-type/<int:pk>/remove/", views.remove_entity_type_view, name="remove_entity_type"),
]
```

- [ ] **Step 6: Commit**

```bash
git add entity/views.py entity/urls.py
git commit -m "feat: multi-type assessment flow + entity type management views"
```

---

### Task 6: HTMX Partial Templates

**Files:**
- Create: `templates/entity/partials/entity_types.html`
- Create: `templates/entity/partials/sector_fields.html`

- [ ] **Step 1: Create partials directory and entity_types partial**

```bash
mkdir -p templates/entity/partials
```

Create `templates/entity/partials/entity_types.html`:

```html
<ul style="list-style: none; padding: 0; margin: 0;">
  {% for et in entity_types %}
  <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0;">
    <span>{{ et.sector_label }} / {{ et.label }}</span>
    {% if entity_types|length > 1 %}
    <form method="post" action="{% url 'remove_entity_type' et.pk %}" style="display:inline;"
          hx-post="{% url 'remove_entity_type' et.pk %}"
          hx-target="#entity-types-list"
          hx-swap="innerHTML">
      {% csrf_token %}
      <button type="submit" style="background:none;border:none;color:var(--cs-significant);cursor:pointer;padding:0;font-size:0.8rem;" onclick="return confirm('Remove this entity type?')">×</button>
    </form>
    {% endif %}
  </li>
  {% endfor %}
</ul>
```

- [ ] **Step 2: Create sector_fields partial**

Create `templates/entity/partials/sector_fields.html`:

```html
{% if "energy" in sectors %}
<fieldset>
  <legend style="color: var(--cs-navy); font-size: 0.9rem;">Electricity (LU)</legend>
  <div class="grid">
    <label>PODs affected <input type="number" name="pods_affected" min="0" value=""></label>
    <label>Voltage level
      <select name="voltage_level">
        <option value="">—</option>
        <option value="lv">Low voltage</option>
        <option value="mv">Medium voltage</option>
        <option value="hv_ehv">HV/EHV</option>
      </select>
    </label>
    <label>SCADA unavailable (min) <input type="number" name="scada_unavailable_min" min="0" value=""></label>
  </div>
</fieldset>
{% endif %}

{% if "transport" in sectors %}
<fieldset>
  <legend style="color: var(--cs-navy); font-size: 0.9rem;">Rail (LU)</legend>
  <div class="grid">
    <label>Trains cancelled % <input type="number" name="trains_cancelled_pct" min="0" max="100" step="0.1" value=""></label>
    <label>Slots impacted <input type="number" name="slots_impacted" min="0" value=""></label>
  </div>
</fieldset>
{% endif %}

{% if "health" in sectors %}
<fieldset>
  <legend style="color: var(--cs-navy); font-size: 0.9rem;">Health (LU)</legend>
  <div class="grid">
    <label>Persons with health impact <input type="number" name="persons_health_impact" min="0" value=""></label>
    <label>Analyses affected % <input type="number" name="analyses_affected_pct" min="0" max="100" step="0.1" value=""></label>
  </div>
</fieldset>
{% endif %}
```

- [ ] **Step 3: Commit**

```bash
git add templates/entity/partials/
git commit -m "feat: HTMX partials for entity types list and sector-specific fields"
```

---

### Task 7: Update Dashboard Template

**Files:**
- Modify: `templates/entity/dashboard.html`

- [ ] **Step 1: Replace `templates/entity/dashboard.html`**

Replace the profile section (lines 4-11) and add the entity type management UI. Full replacement:

```html
{% extends "base.html" %}
{% block title %}Dashboard — CyberScale{% endblock %}

{% block content %}
<div class="cs-profile">
  <div class="cs-profile-icon">{{ entity.organisation_name|truncatechars:1 }}</div>
  <div class="cs-profile-info">
    <h3>{{ entity.organisation_name }}</h3>
    <p>{{ entity.ms_established }}</p>
  </div>
</div>

<div class="cs-card">
  <h3>Registered Entity Types</h3>
  <div id="entity-types-list">
    {% include "entity/partials/entity_types.html" with entity_types=entity.entity_types.all %}
  </div>

  <details style="margin-top: 0.75rem;">
    <summary style="font-size: 0.85rem;">Add entity type</summary>
    <form method="post" action="{% url 'add_entity_type' %}"
          hx-post="{% url 'add_entity_type' %}"
          hx-target="#entity-types-list"
          hx-swap="innerHTML"
          style="margin-top: 0.5rem;">
      {% csrf_token %}
      <div class="grid">
        <label>Sector
          <select name="sector" id="add_sector"
                  hx-get="{% url 'htmx_entity_types' %}"
                  hx-target="#add_entity_type"
                  hx-trigger="change"
                  hx-swap="innerHTML">
            {% for value, label in sector_choices %}
              <option value="{{ value }}">{{ label }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Entity type
          <select name="entity_type" id="add_entity_type">
            <option value="">— Select sector first —</option>
          </select>
        </label>
        <label>&nbsp;<button type="submit" style="margin-top: 0;">Add</button></label>
      </div>
    </form>
  </details>
</div>

<a href="{% url 'assessment_form' %}" role="button" style="margin-top: 1rem; display: inline-block;">New Incident Assessment</a>

{% if assessments %}
<div class="cs-card" style="margin-top: 1.5rem;">
  <h3>Recent Assessments</h3>
  <figure>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Date</th>
          <th>Description</th>
          <th>Status</th>
          <th>Types</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for a in assessments %}
        <tr>
          <td>{{ a.pk }}</td>
          <td>{{ a.created_at|date:"Y-m-d H:i" }}</td>
          <td>{{ a.description|truncatewords:10 }}</td>
          <td>
            {% if a.status == "draft" %}
              <span class="badge badge-draft">DRAFT</span>
            {% elif a.result_significance_label == "SIGNIFICANT" or a.result_significance_label == "LIKELY" %}
              <span class="badge badge-significant">{{ a.result_significance_label }}</span>
            {% elif a.result_significance_label == "NOT SIGNIFICANT" or a.result_significance_label == "UNLIKELY" %}
              <span class="badge badge-not-significant">{{ a.result_significance_label }}</span>
            {% else %}
              <span class="badge badge-undetermined">{{ a.result_significance_label }}</span>
            {% endif %}
          </td>
          <td>
            {% if a.affected_entity_types %}
              <small>{{ a.affected_entity_types|length }} type{{ a.affected_entity_types|length|pluralize }}</small>
            {% else %}
              <small>{{ a.sector }}/{{ a.entity_type }}</small>
            {% endif %}
          </td>
          <td>
            {% if a.status == "draft" %}
              <a href="{% url 'resume_draft' a.pk %}">Resume</a>
              &middot;
              <form method="post" action="{% url 'delete_draft' a.pk %}" style="display:inline;">
                {% csrf_token %}
                <button type="submit" style="background:none;border:none;color:var(--cs-significant);cursor:pointer;padding:0;font-size:inherit;text-decoration:underline;" onclick="return confirm('Delete draft #{{ a.pk }}?')">Delete</button>
              </form>
            {% else %}
              <a href="{% url 'assessment_result' a.pk %}">View</a>
              &middot; <a href="{% url 'assessment_pdf' a.pk %}">PDF</a>
              &middot; <a href="{% url 'assessment_misp_json' a.pk %}">MISP</a>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </figure>
</div>
{% else %}
  <p style="margin-top: 1.5rem; color: var(--cs-text-muted);">No assessments yet. Create your first incident assessment above.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 2: Update `dashboard_view` to pass sector choices**

In `entity/views.py`, update the `dashboard_view` to include sector choices:

```python
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
```

- [ ] **Step 3: Commit**

```bash
git add templates/entity/dashboard.html entity/views.py
git commit -m "feat: dashboard with entity type management and multi-type display"
```

---

### Task 8: Update Assessment Form Template

**Files:**
- Modify: `templates/entity/assessment_form.html`

- [ ] **Step 1: Replace `templates/entity/assessment_form.html`**

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
  <li class="cs-step active"><span class="cs-step-num">3</span> Sector</li>
  <li class="cs-step"><span class="cs-step-num">4</span> Result</li>
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
           hx-get="{% url 'htmx_sector_fields' %}"
           hx-target="#sector-specific-fields"
           hx-trigger="change"
           hx-include="[name='affected_entity_types']"
           hx-vals='js:{"sectors": Array.from(document.querySelectorAll("[name=affected_entity_types]:checked")).map(e => e.value.split(":")[0]).join(",")}'>
        {{ form1.affected_entity_types }}
      </div>
    {% endif %}
    {% if form1.affected_entity_types.errors %}<small style="color: var(--cs-significant);">{{ form1.affected_entity_types.errors.0 }}</small>{% endif %}

    <label>Member states affected
      {{ form1.ms_affected }}
    </label>
  </fieldset>

  <fieldset>
    <legend>Step 2 — Impact Assessment</legend>
    <div class="grid">
      <label>Service impact {{ form2.service_impact }}</label>
      <label>Data impact {{ form2.data_impact }}</label>
    </div>
    <div class="grid">
      <label>Safety impact {{ form2.safety_impact }}</label>
      <label>Financial impact {{ form2.financial_impact }}</label>
    </div>
    <div class="grid">
      <label>Affected persons count {{ form2.affected_persons_count }}</label>
      <label>Impact duration (hours) {{ form2.impact_duration_hours }}</label>
    </div>
    <div class="grid">
      <label>{{ form2.suspected_malicious }} Suspected malicious</label>
      <label>{{ form2.physical_access_breach }} Physical access breach (IR only)</label>
    </div>
  </fieldset>

  <div id="sector-specific-fields">
    {# Populated by HTMX when entity type checkboxes change #}
    {# Or pre-rendered for single entity type #}
    {% if registered_types|length == 1 and registered_types.0.sector in "energy,transport,health" %}
      {% include "entity/partials/sector_fields.html" with sectors=registered_types.0.sector %}
    {% endif %}
  </div>

  <div class="cs-actions">
    <button type="submit" name="run_assessment">Run Assessment</button>
    <button type="submit" name="save_draft" class="secondary">Save Draft</button>
  </div>
</form>
{% endblock %}
```

- [ ] **Step 2: Commit**

```bash
git add templates/entity/assessment_form.html
git commit -m "feat: assessment form with entity type multi-select and dynamic sector fields"
```

---

### Task 9: Update Result Page + PDF + MISP for Multi-Type

**Files:**
- Modify: `templates/entity/assessment_result.html`
- Modify: `templates/entity/assessment_pdf.html`
- Modify: `entity/misp_export.py`
- Modify: `entity/views.py` (MISP view)

- [ ] **Step 1: Replace `templates/entity/assessment_result.html`**

```html
{% extends "base.html" %}
{% block title %}Assessment #{{ assessment.pk }} — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>Assessment #{{ assessment.pk }}</h2>
  <p>{{ entity.organisation_name }} — {{ assessment.created_at|date:"Y-m-d H:i" }} UTC</p>
</div>

{# Overall significance banner #}
{% if assessment.result_significance_label == "SIGNIFICANT" or assessment.result_significance_label == "LIKELY" %}
  <div class="cs-sig-banner significant">
{% elif assessment.result_significance_label == "NOT SIGNIFICANT" or assessment.result_significance_label == "UNLIKELY" %}
  <div class="cs-sig-banner not-significant">
{% else %}
  <div class="cs-sig-banner undetermined">
{% endif %}
    <span class="cs-sig-label">{{ assessment.result_significance_label }}</span>
    <span class="cs-sig-meta">
      Overall determination across {{ assessment.affected_entity_types|length }} entity type{{ assessment.affected_entity_types|length|pluralize }}
    </span>
  </div>

{# Per-entity-type result cards #}
{% for r in assessment.assessment_results %}
<div class="cs-card">
  <h3>{{ r.sector|default:""|title }} / {{ r.entity_type|default:"" }}</h3>
  <div class="grid">
    <div>
      <p style="font-size: 1.2rem;">
        {% if r.significance_label == "SIGNIFICANT" or r.significance_label == "LIKELY" %}
          <span class="badge badge-significant">{{ r.significance_label }}</span>
        {% elif r.significance_label == "NOT SIGNIFICANT" or r.significance_label == "UNLIKELY" %}
          <span class="badge badge-not-significant">{{ r.significance_label }}</span>
        {% else %}
          <span class="badge badge-undetermined">{{ r.significance_label }}</span>
        {% endif %}
        <span class="badge badge-model">{{ r.model }}</span>
      </p>
      {% if r.framework %}<p><strong>Framework:</strong> {{ r.framework }}</p>{% endif %}
      {% if r.competent_authority %}<p><strong>Authority:</strong> {{ r.competent_authority }}</p>{% endif %}
    </div>
    <div>
      {% if r.triggered_criteria %}
        <p><strong>Triggered criteria:</strong></p>
        <ul class="cs-criteria-list">
          {% for c in r.triggered_criteria %}
            <li>{{ c }}</li>
          {% endfor %}
        </ul>
      {% endif %}
    </div>
  </div>
  {% if r.early_warning.recommended %}
    <p style="margin-top: 0.5rem;"><span class="badge badge-significant">EARLY WARNING</span> Deadline: {{ r.early_warning.deadline }}</p>
  {% endif %}
</div>
{% empty %}
{# Fallback for old assessments without assessment_results #}
<div class="cs-card">
  <h3>{{ assessment.sector|title }} / {{ assessment.entity_type }}</h3>
  <p><span class="badge badge-model">{{ assessment.result_model }}</span></p>
  {% if assessment.result_framework %}<p><strong>Framework:</strong> {{ assessment.result_framework }}</p>{% endif %}
  {% if assessment.result_competent_authority %}<p><strong>Authority:</strong> {{ assessment.result_competent_authority }}</p>{% endif %}
  {% if assessment.result_criteria %}
    <ul class="cs-criteria-list">
      {% for c in assessment.result_criteria %}<li>{{ c }}</li>{% endfor %}
    </ul>
  {% endif %}
</div>
{% endfor %}

{# Early warning (overall) #}
{% if assessment.result_early_warning.recommended %}
<div class="cs-card">
  <h3>Early Warning</h3>
  <p><span class="badge badge-significant">RECOMMENDED</span></p>
  <p><strong>Deadline:</strong> {{ assessment.result_early_warning.deadline }} from awareness</p>
  {% if assessment.result_early_warning.required_content %}
    <p><strong>Required content:</strong></p>
    <ul>
      {% for item in assessment.result_early_warning.required_content %}<li>{{ item }}</li>{% endfor %}
    </ul>
  {% endif %}
  {% if assessment.result_early_warning.next_step %}
    <p><strong>Next steps:</strong> {{ assessment.result_early_warning.next_step }}</p>
  {% endif %}
</div>
{% endif %}

{# Impact summary #}
<div class="cs-card">
  <h3>Impact Summary</h3>
  <table>
    <tbody>
      <tr><td><strong>Service</strong></td><td>{{ assessment.service_impact }}{% if assessment.impact_duration_hours %} ({{ assessment.impact_duration_hours }}h){% endif %}</td></tr>
      <tr><td><strong>Data</strong></td><td>{{ assessment.data_impact }}</td></tr>
      <tr><td><strong>Safety</strong></td><td>{{ assessment.safety_impact }}</td></tr>
      <tr><td><strong>Financial</strong></td><td>{{ assessment.financial_impact }}</td></tr>
      <tr><td><strong>Affected persons</strong></td><td>{{ assessment.affected_persons_count|default:"0" }}</td></tr>
      <tr><td><strong>Suspected malicious</strong></td><td>{% if assessment.suspected_malicious %}Yes{% else %}No{% endif %}</td></tr>
    </tbody>
  </table>
</div>

<div class="cs-card">
  <h3>Incident Description</h3>
  <p>{{ assessment.description }}</p>
</div>

{# Actions #}
<div class="cs-actions">
  <a href="{% url 'assessment_pdf' assessment.pk %}" role="button">Download PDF</a>
  {% if assessment.assessment_results|length > 1 %}
    {% for r in assessment.assessment_results %}
      <a href="{% url 'assessment_misp_json' assessment.pk %}?type_index={{ forloop.counter0 }}" role="button" class="secondary">MISP: {{ r.sector|title }}</a>
    {% endfor %}
  {% else %}
    <a href="{% url 'assessment_misp_json' assessment.pk %}" role="button" class="secondary">Download MISP JSON</a>
  {% endif %}
  <a href="{% url 'dashboard' %}" role="button" class="outline">Back to Dashboard</a>
</div>

<br>
<small style="color: var(--cs-text-muted);">Generated by CyberScale v1.0.0. Assessment is advisory — notification decision remains the entity's responsibility.</small>
{% endblock %}
```

- [ ] **Step 2: Update `entity/misp_export.py` for per-type export**

Add a new function to `entity/misp_export.py` after `build_misp_event`:

```python
def build_misp_event_for_type(assessment, entity, type_result: dict) -> dict:
    """Build a MISP event for a specific entity type result.

    Used when an assessment covers multiple entity types.
    """
    event_uuid = str(uuid.uuid4())

    sig_label = type_result.get("significance_label", "")
    if sig_label in ("SIGNIFICANT", "LIKELY"):
        threat_level_id = "1"
        sig_tag = "significant"
    elif sig_label in ("NOT SIGNIFICANT", "UNLIKELY"):
        threat_level_id = "3"
        sig_tag = "not-significant"
    else:
        threat_level_id = "2"
        sig_tag = "undetermined"

    ew = type_result.get("early_warning", {})
    criteria = type_result.get("triggered_criteria", [])
    criteria_text = " | ".join(criteria) if isinstance(criteria, list) and criteria else ""

    attributes = [
        _attr("sector", "text", type_result.get("sector", "")),
        _attr("entity-type", "text", type_result.get("entity_type", "")),
        _attr("ms-established", "text", entity.ms_established),
        _attr("description", "text", assessment.description),
        _attr("service-impact", "text", assessment.service_impact),
        _attr("data-impact", "text", assessment.data_impact),
        _attr("safety-impact", "text", assessment.safety_impact),
        _attr("financial-impact", "text", assessment.financial_impact),
        _attr("affected-persons-count", "counter", str(assessment.affected_persons_count)),
        _attr("impact-duration-hours", "counter", str(assessment.impact_duration_hours)),
        _attr("suspected-malicious", "boolean", "1" if assessment.suspected_malicious else "0"),
        _attr("significant-incident", "boolean", "1" if type_result.get("significant_incident") else "0"),
        _attr("significance-model", "text", type_result.get("model", "")),
        _attr("competent-authority", "text", type_result.get("competent_authority", "")),
        _attr("framework", "text", type_result.get("framework", "")),
        _attr("early-warning-recommended", "boolean", "1" if ew.get("recommended") else "0"),
        _attr("early-warning-deadline", "text", ew.get("deadline", "")),
    ]
    if criteria_text:
        attributes.append(_attr("triggered-criteria", "text", criteria_text))

    tlp = entity.misp_default_tlp or "tlp:amber"

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {type_result.get('sector', '')} / {type_result.get('entity_type', '')}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "1",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:phase="phase-2"'},
                {"name": f'cyberscale:significance-model="{type_result.get("model", "")}"'},
                {"name": f'nis2:significance="{sig_tag}"'},
                {"name": tlp},
            ],
            "Object": [
                {
                    "name": "cyberscale-entity-assessment",
                    "meta-category": "misc",
                    "uuid": str(uuid.uuid4()),
                    "Attribute": attributes,
                }
            ],
        }
    }
```

- [ ] **Step 3: Update MISP JSON view for per-type export**

In `entity/views.py`, replace the `assessment_misp_json_view` function with:

```python
@login_required
def assessment_misp_json_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    from .misp_export import build_misp_event, build_misp_event_for_type
    import uuid as uuid_mod

    # Check if a specific type index is requested
    type_index = request.GET.get("type_index")

    if type_index is not None and assessment.assessment_results:
        idx = int(type_index)
        if 0 <= idx < len(assessment.assessment_results):
            type_result = assessment.assessment_results[idx]
            event = build_misp_event_for_type(assessment, entity, type_result)
            sector = type_result.get("sector", "unknown")
            filename = f"cyberscale-assessment-{assessment.pk}-{sector}.misp.json"
        else:
            event = build_misp_event(assessment, entity)
            filename = f"cyberscale-assessment-{assessment.pk}.misp.json"
    else:
        if not assessment.misp_event_uuid:
            assessment.misp_event_uuid = str(uuid_mod.uuid4())
            assessment.save(update_fields=["misp_event_uuid"])
        event = build_misp_event(assessment, entity)
        filename = f"cyberscale-assessment-{assessment.pk}.misp.json"

    json_bytes = json.dumps(event, indent=2, ensure_ascii=False).encode("utf-8")

    Submission.objects.create(
        assessment=assessment, target="misp_json_download", status="success"
    )

    response = HttpResponse(json_bytes, content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
```

- [ ] **Step 4: Commit**

```bash
git add templates/entity/assessment_result.html entity/misp_export.py entity/views.py
git commit -m "feat: multi-type result page, per-type MISP export"
```

---

### Task 10: Update PDF Template + Admin + Verification

**Files:**
- Modify: `templates/entity/assessment_pdf.html`
- Modify: `entity/admin.py`

- [ ] **Step 1: Update PDF template for multi-type results**

In `templates/entity/assessment_pdf.html`, replace the significance section and everything after it (from `<h2>Significance Determination</h2>` through the criteria section) with a per-type loop. Replace lines 43-65 with:

```html
<h2>Significance Determination</h2>
{% if assessment.result_significance_label == "SIGNIFICANT" or assessment.result_significance_label == "LIKELY" %}
  <div class="sig-box sig-significant"><span class="sig-label">{{ assessment.result_significance_label }}</span></div>
{% elif assessment.result_significance_label == "NOT SIGNIFICANT" or assessment.result_significance_label == "UNLIKELY" %}
  <div class="sig-box sig-not-significant"><span class="sig-label">{{ assessment.result_significance_label }}</span></div>
{% else %}
  <div class="sig-box sig-undetermined"><span class="sig-label">{{ assessment.result_significance_label|default:"UNDETERMINED" }}</span></div>
{% endif %}

{% if assessment.assessment_results %}
  <p style="color: #6c757d; font-size: 10pt;">Overall determination across {{ assessment.assessment_results|length }} entity type{{ assessment.assessment_results|length|pluralize }}</p>

  {% for r in assessment.assessment_results %}
  <h2>{{ r.sector|default:""|title }} / {{ r.entity_type|default:"" }}</h2>
  <table>
    <tr><th>Significance</th><td>{{ r.significance_label }}</td></tr>
    <tr><th>Model</th><td>{{ r.model }}</td></tr>
    {% if r.framework %}<tr><th>Framework</th><td>{{ r.framework }}</td></tr>{% endif %}
    {% if r.competent_authority %}<tr><th>Competent authority</th><td>{{ r.competent_authority }}</td></tr>{% endif %}
  </table>
  {% if r.triggered_criteria %}
  <ul class="criteria-list">
    {% for c in r.triggered_criteria %}<li>{{ c }}</li>{% endfor %}
  </ul>
  {% endif %}
  {% if r.early_warning.recommended %}
    <p class="ew-recommended">Early warning recommended — {{ r.early_warning.deadline }}</p>
  {% endif %}
  {% endfor %}
{% else %}
  <table>
    {% if assessment.result_framework %}<tr><th>Framework</th><td>{{ assessment.result_framework }}</td></tr>{% endif %}
    {% if assessment.result_competent_authority %}<tr><th>Competent authority</th><td>{{ assessment.result_competent_authority }}</td></tr>{% endif %}
    <tr><th>Assessment model</th><td>{{ assessment.result_model }}</td></tr>
  </table>
  {% if assessment.result_criteria %}
  <ul class="criteria-list">
    {% for criterion in assessment.result_criteria %}<li>{{ criterion }}</li>{% endfor %}
  </ul>
  {% endif %}
{% endif %}
```

- [ ] **Step 2: Register EntityType in admin**

In `entity/admin.py`, add after the imports:

```python
from .models import Assessment, Entity, EntityType, Submission
```

Add an `EntityTypeInline` and update `EntityAdmin`:

```python
class EntityTypeInline(admin.TabularInline):
    model = EntityType
    fields = ("sector", "entity_type", "added_at")
    readonly_fields = ("added_at",)
    extra = 1


@admin.register(EntityType)
class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ("entity", "sector", "entity_type", "added_at")
    list_filter = ("sector",)
    search_fields = ("entity__organisation_name", "entity_type")
```

Update `EntityAdmin` to remove `sector`/`entity_type` from `list_display` and add the inline:

```python
@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "ms_established", "competent_authority")
    list_filter = ("ms_established",)
    search_fields = ("organisation_name", "user__username")
    inlines = [EntityTypeInline, AssessmentInline]
```

- [ ] **Step 3: Run collectstatic and verify**

```bash
docker compose exec cyberscale-web python manage.py collectstatic --noinput
```

Test the full flow in the browser:
1. Login, verify entity types shown on dashboard
2. Add a second entity type (e.g., drinking_water_supplier)
3. Create assessment selecting both entity types
4. Verify result page shows per-type cards
5. Verify PDF and MISP downloads work

- [ ] **Step 4: Commit**

```bash
git add templates/entity/assessment_pdf.html entity/admin.py
git commit -m "feat: multi-type PDF, EntityType admin, end-to-end verification"
```
