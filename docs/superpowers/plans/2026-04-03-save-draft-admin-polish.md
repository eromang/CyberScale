# Save Draft + Django Admin Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add save/resume/delete draft assessments and polish Django admin with inlines, filters, and CSV export.

**Architecture:** Draft functionality is added to the existing assessment form view (detect which button was clicked) with two new views for resume and delete. Admin gets assessment inlines on Entity, expanded filters/display, and a CSV export action.

**Tech Stack:** Django 5.x, HTMX, existing entity app

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `entity/views.py` | Modify | Add draft save logic to `assessment_form_view`, new `resume_draft_view`, new `delete_draft_view` |
| `entity/urls.py` | Modify | Add draft resume + delete URL patterns |
| `entity/admin.py` | Rewrite | Assessment inline, expanded list views, CSV export action |
| `templates/entity/assessment_form.html` | Modify | Add "Save Draft" button, hidden field for draft_pk |
| `templates/entity/dashboard.html` | Rewrite | Conditional draft/completed display, resume/delete links |
| `static/css/cyberscale.css` | Modify | Add `.badge-draft` style |

---

### Task 1: Add Draft Badge CSS

**Files:**
- Modify: `static/css/cyberscale.css`

- [ ] **Step 1: Add the draft badge style**

Add after the `.badge-model` rule (around line 175) in `static/css/cyberscale.css`:

```css
.badge-draft {
  background: var(--cs-steel);
  color: #fff;
}
```

- [ ] **Step 2: Commit**

```bash
git add static/css/cyberscale.css
git commit -m "feat: add draft badge CSS style"
```

---

### Task 2: Save Draft Logic in Views

**Files:**
- Modify: `entity/views.py`

- [ ] **Step 1: Modify `assessment_form_view` to handle draft saves**

Replace the entire `assessment_form_view` function (lines 69-150) in `entity/views.py` with:

```python
@login_required
def assessment_form_view(request, draft_pk=None):
    entity = get_object_or_404(Entity, user=request.user)

    # Load existing draft if resuming
    draft = None
    if draft_pk:
        draft = get_object_or_404(Assessment, pk=draft_pk, entity=entity, status="draft")

    if request.method == "POST":
        form1 = AssessmentStep1Form(request.POST)
        form2 = AssessmentStep2Form(request.POST)
        form3 = AssessmentStep3Form(request.POST)

        # Check which button was clicked
        is_draft = "save_draft" in request.POST

        if form1.is_valid() and form2.is_valid() and form3.is_valid():
            sector_specific = form3.get_sector_specific()
            ms_affected = form1.cleaned_data.get("ms_affected", [])

            # Common fields for both draft and completed
            fields = dict(
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
            )

            if is_draft:
                # Save as draft — no engine run
                if draft:
                    for k, v in fields.items():
                        setattr(draft, k, v)
                    draft.save()
                    assessment = draft
                else:
                    assessment = Assessment.objects.create(
                        entity=entity, status="draft", **fields,
                    )
                from django.contrib import messages
                messages.success(request, f"Draft #{assessment.pk} saved.")
                return redirect("dashboard")
            else:
                # Run assessment engine
                result = run_entity_assessment(
                    description=fields["description"],
                    sector=entity.sector,
                    entity_type=entity.entity_type,
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

                result_fields = dict(
                    status="completed",
                    result_significance=sig_bool,
                    result_significance_label=sig_label,
                    result_model=result.get("model", ""),
                    result_criteria=sig_data.get("triggered_criteria", []),
                    result_framework=result.get("framework", ""),
                    result_competent_authority=result.get("competent_authority", ""),
                    result_early_warning=result.get("early_warning", {}),
                    result_raw=result,
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
        # Pre-populate forms from draft if resuming
        if draft:
            form1 = AssessmentStep1Form(initial={
                "description": draft.description,
                "ms_affected": draft.ms_affected,
            })
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
            form1 = AssessmentStep1Form()
            form2 = AssessmentStep2Form()
            form3 = AssessmentStep3Form()

    return render(request, "entity/assessment_form.html", {
        "entity": entity,
        "form1": form1,
        "form2": form2,
        "form3": form3,
        "draft": draft,
    })
```

- [ ] **Step 2: Add the delete draft view**

Add after `assessment_form_view` in `entity/views.py`:

```python
@login_required
def delete_draft_view(request, pk):
    entity = get_object_or_404(Entity, user=request.user)
    draft = get_object_or_404(Assessment, pk=pk, entity=entity, status="draft")
    if request.method == "POST":
        draft.delete()
        from django.contrib import messages
        messages.success(request, "Draft deleted.")
    return redirect("dashboard")
```

- [ ] **Step 3: Verify views import correctly**

```bash
docker compose exec cyberscale-web python -c "from entity.views import assessment_form_view, delete_draft_view; print('OK')"
```
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add entity/views.py
git commit -m "feat: add save draft and delete draft logic to views"
```

---

### Task 3: Draft URL Patterns

**Files:**
- Modify: `entity/urls.py`

- [ ] **Step 1: Add draft resume and delete URL patterns**

Replace the entire contents of `entity/urls.py` with:

```python
from django.contrib.auth.views import LogoutView
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("assess/", views.assessment_form_view, name="assessment_form"),
    path("assess/draft/<int:draft_pk>/", views.assessment_form_view, name="resume_draft"),
    path("assess/draft/<int:pk>/delete/", views.delete_draft_view, name="delete_draft"),
    path("assess/<int:pk>/", views.assessment_result_view, name="assessment_result"),
    path("assess/<int:pk>/pdf/", views.assessment_pdf_view, name="assessment_pdf"),
    path("assess/<int:pk>/misp-json/", views.assessment_misp_json_view, name="assessment_misp_json"),
    path("htmx/entity-types/", views.entity_types_for_sector, name="htmx_entity_types"),
]
```

Key: `resume_draft` reuses `assessment_form_view` with the `draft_pk` kwarg.

- [ ] **Step 2: Commit**

```bash
git add entity/urls.py
git commit -m "feat: add draft resume and delete URL patterns"
```

---

### Task 4: Update Assessment Form Template

**Files:**
- Modify: `templates/entity/assessment_form.html`

- [ ] **Step 1: Replace the form template**

Replace the entire contents of `templates/entity/assessment_form.html` with:

```html
{% extends "base.html" %}
{% block title %}{% if draft %}Resume Draft #{{ draft.pk }}{% else %}New Assessment{% endif %} — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>{% if draft %}Resume Draft #{{ draft.pk }}{% else %}Incident Assessment{% endif %}</h2>
  <p>{{ entity.organisation_name }} — {{ entity.sector|title }} / {{ entity.entity_type }} ({{ entity.ms_established }})</p>
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

    <label>Member states affected
      {{ form1.ms_affected }}
    </label>
    <p><small style="color: var(--cs-text-muted);">Sector and entity type pre-filled from your profile: <strong>{{ entity.sector }}</strong> / <strong>{{ entity.entity_type }}</strong></small></p>
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

  <details>
    <summary>Step 3 — Sector-Specific Fields (optional)</summary>
    <fieldset>
      <p><small style="color: var(--cs-text-muted);">Fill these if your entity is in a Luxembourg-regulated sector with ILR thresholds.</small></p>

      <h4 style="color: var(--cs-navy);">Electricity</h4>
      <div class="grid">
        <label>PODs affected {{ form3.pods_affected }}</label>
        <label>Voltage level {{ form3.voltage_level }}</label>
        <label>SCADA unavailable (min) {{ form3.scada_unavailable_min }}</label>
      </div>

      <h4 style="color: var(--cs-navy);">Rail</h4>
      <div class="grid">
        <label>Trains cancelled % {{ form3.trains_cancelled_pct }}</label>
        <label>Slots impacted {{ form3.slots_impacted }}</label>
      </div>

      <h4 style="color: var(--cs-navy);">Health</h4>
      <div class="grid">
        <label>Persons with health impact {{ form3.persons_health_impact }}</label>
        <label>Analyses affected % {{ form3.analyses_affected_pct }}</label>
      </div>
    </fieldset>
  </details>

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
git commit -m "feat: add Save Draft button to assessment form"
```

---

### Task 5: Update Dashboard Template for Drafts

**Files:**
- Modify: `templates/entity/dashboard.html`

- [ ] **Step 1: Replace the dashboard template**

Replace the entire contents of `templates/entity/dashboard.html` with:

```html
{% extends "base.html" %}
{% block title %}Dashboard — CyberScale{% endblock %}

{% block content %}
<div class="cs-profile">
  <div class="cs-profile-icon">{{ entity.organisation_name|truncatechars:1 }}</div>
  <div class="cs-profile-info">
    <h3>{{ entity.organisation_name }}</h3>
    <p>{{ entity.sector|title }} / {{ entity.entity_type }} — {{ entity.ms_established }}</p>
  </div>
</div>

<a href="{% url 'assessment_form' %}" role="button">New Incident Assessment</a>

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
          <th>Model</th>
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
            {% if a.status == "draft" %}
              <span style="color: var(--cs-text-muted);">—</span>
            {% else %}
              <span class="badge badge-model">{{ a.result_model }}</span>
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

- [ ] **Step 2: Commit**

```bash
git add templates/entity/dashboard.html
git commit -m "feat: dashboard shows drafts with resume/delete actions"
```

---

### Task 6: Django Admin Polish

**Files:**
- Rewrite: `entity/admin.py`

- [ ] **Step 1: Replace `entity/admin.py` with the polished version**

```python
import csv

from django.contrib import admin
from django.http import HttpResponse

from .models import Assessment, Entity, Submission


class AssessmentInline(admin.TabularInline):
    model = Assessment
    fields = ("id", "created_at", "status", "result_significance_label", "result_model", "result_framework")
    readonly_fields = ("id", "created_at", "status", "result_significance_label", "result_model", "result_framework")
    extra = 0
    max_num = 0
    show_change_link = True
    ordering = ("-created_at",)

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "sector", "entity_type", "ms_established", "competent_authority")
    list_filter = ("sector", "ms_established")
    search_fields = ("organisation_name", "user__username")
    inlines = [AssessmentInline]


def export_assessments_csv(modeladmin, request, queryset):
    """Export selected assessments as CSV."""
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="cyberscale-assessments.csv"'
    writer = csv.writer(response)
    writer.writerow([
        "ID", "Entity", "Sector", "Entity Type", "Status",
        "Significance", "Framework", "Authority", "Model", "Created",
    ])
    for a in queryset.select_related("entity"):
        writer.writerow([
            a.id,
            a.entity.organisation_name,
            a.sector,
            a.entity_type,
            a.status,
            a.result_significance_label,
            a.result_framework,
            a.result_competent_authority,
            a.result_model,
            a.created_at.strftime("%Y-%m-%d %H:%M"),
        ])
    return response

export_assessments_csv.short_description = "Export selected as CSV"


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = (
        "id", "entity", "status", "result_significance_label",
        "result_framework", "result_competent_authority", "result_model", "created_at",
    )
    list_filter = ("status", "result_significance_label", "result_model", "result_framework", "sector")
    search_fields = ("entity__organisation_name", "description")
    date_hierarchy = "created_at"
    readonly_fields = (
        "result_significance", "result_significance_label", "result_model",
        "result_criteria", "result_framework", "result_competent_authority",
        "result_early_warning", "result_raw",
    )
    actions = [export_assessments_csv]


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "assessment", "get_entity", "target", "status", "submitted_at")
    list_filter = ("target", "status")
    date_hierarchy = "submitted_at"
    raw_id_fields = ("assessment",)

    @admin.display(description="Entity")
    def get_entity(self, obj):
        return obj.assessment.entity.organisation_name
```

- [ ] **Step 2: Verify admin loads**

```bash
docker compose exec cyberscale-web python -c "
import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberscale_web.settings'
django.setup()
from django.contrib.admin.sites import site
print('Registered:', [m.__name__ for m in site._registry])
"
```
Expected: output includes `Entity`, `Assessment`, `Submission`

- [ ] **Step 3: Commit**

```bash
git add entity/admin.py
git commit -m "feat: polished Django admin with inlines, filters, CSV export"
```

---

### Task 7: End-to-End Verification

- [ ] **Step 1: Collect static files**

```bash
docker compose exec cyberscale-web python manage.py collectstatic --noinput
```

- [ ] **Step 2: Test save draft flow**

1. Open http://localhost:8000/assess/
2. Fill in description: "Test draft save"
3. Click "Save Draft"
4. Verify redirect to dashboard with success message
5. Verify dashboard shows DRAFT badge and Resume/Delete links

- [ ] **Step 3: Test resume draft flow**

1. Click "Resume" on the draft in dashboard
2. Verify form is pre-populated with "Test draft save"
3. Fill in remaining impact fields
4. Click "Run Assessment"
5. Verify redirect to result page with significance determination
6. Verify dashboard now shows completed assessment (no longer draft)

- [ ] **Step 4: Test delete draft**

1. Create another draft
2. Click "Delete" on the draft
3. Confirm the deletion
4. Verify draft is removed from dashboard

- [ ] **Step 5: Test Django admin**

1. Open http://localhost:8000/admin/
2. Click on Entities — verify assessment inline shows on entity detail
3. Click on Assessments — verify date hierarchy, expanded filters, column headers
4. Select assessments → "Export selected as CSV" — verify CSV downloads with correct data

- [ ] **Step 6: Verify existing flows still work**

```bash
curl -s -c /tmp/cs_cookies -b /tmp/cs_cookies http://localhost:8000/assess/1/pdf/ -o /dev/null -w "%{http_code}"
curl -s -c /tmp/cs_cookies -b /tmp/cs_cookies http://localhost:8000/assess/1/misp-json/ -o /dev/null -w "%{http_code}"
```
Expected: both return `200`
