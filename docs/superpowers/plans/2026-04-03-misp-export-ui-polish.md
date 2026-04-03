# MISP JSON Export + UI Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add MISP JSON export for assessments and overhaul the UI to a professional/institutional look.

**Architecture:** New `entity/misp_export.py` module builds MISP event JSON from Assessment model data. All templates rewritten with a navy/institutional color scheme using a custom `static/css/cyberscale.css` layered on Pico CSS. HTMX sector filtering on registration already wired in views, just needs correct template attributes.

**Tech Stack:** Django 5.x, HTMX 2.x, Pico CSS 2.x, WeasyPrint

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `entity/misp_export.py` | Create | Build MISP event JSON dict from Assessment |
| `entity/views.py` | Modify | Add `assessment_misp_json_view` |
| `entity/urls.py` | Modify | Add MISP JSON URL pattern |
| `static/css/cyberscale.css` | Create | All custom styles (institutional theme) |
| `templates/base.html` | Rewrite | Navy nav, CSS link, footer |
| `templates/entity/login.html` | Rewrite | Styled login |
| `templates/entity/register.html` | Rewrite | HTMX sector filtering, styled fieldsets |
| `templates/entity/dashboard.html` | Rewrite | Profile card, cleaner table, MISP JSON links |
| `templates/entity/assessment_form.html` | Rewrite | Step indicators, improved grid |
| `templates/entity/assessment_result.html` | Rewrite | Card layout, MISP JSON button |
| `templates/entity/assessment_pdf.html` | Modify | Navy color alignment with web theme |

---

### Task 1: MISP JSON Export Module

**Files:**
- Create: `entity/misp_export.py`

- [ ] **Step 1: Create the MISP export module**

Create `entity/misp_export.py` with a function that builds the MISP event JSON from an Assessment and Entity:

```python
"""MISP JSON export for CyberScale assessments."""

from __future__ import annotations

import uuid
from datetime import datetime


def build_misp_event(assessment, entity) -> dict:
    """Build a MISP event dict from an Assessment + Entity.

    Follows the cyberscale-entity-assessment object structure
    from product spec section 6.2.
    """
    event_uuid = assessment.misp_event_uuid or str(uuid.uuid4())

    # Map significance to MISP threat level
    sig_label = assessment.result_significance_label
    if sig_label in ("SIGNIFICANT", "LIKELY"):
        threat_level_id = "1"  # High
        sig_tag = "significant"
    elif sig_label in ("NOT SIGNIFICANT", "UNLIKELY"):
        threat_level_id = "3"  # Low
        sig_tag = "not-significant"
    else:
        threat_level_id = "2"  # Medium
        sig_tag = "undetermined"

    # Build attributes list
    attributes = [
        _attr("sector", "text", assessment.sector),
        _attr("entity-type", "text", assessment.entity_type),
        _attr("ms-established", "text", entity.ms_established),
        _attr("description", "text", assessment.description),
        _attr("service-impact", "text", assessment.service_impact),
        _attr("data-impact", "text", assessment.data_impact),
        _attr("safety-impact", "text", assessment.safety_impact),
        _attr("financial-impact", "text", assessment.financial_impact),
        _attr("affected-persons-count", "counter", str(assessment.affected_persons_count)),
        _attr("impact-duration-hours", "counter", str(assessment.impact_duration_hours)),
        _attr("suspected-malicious", "boolean", "1" if assessment.suspected_malicious else "0"),
        _attr("significant-incident", "boolean", "1" if assessment.result_significance else "0"),
        _attr("significance-model", "text", assessment.result_model),
        _attr("competent-authority", "text", assessment.result_competent_authority),
        _attr("framework", "text", assessment.result_framework),
        _attr("early-warning-recommended", "boolean",
              "1" if assessment.result_early_warning.get("recommended") else "0"),
        _attr("early-warning-deadline", "text",
              assessment.result_early_warning.get("deadline", "")),
    ]

    # Triggered criteria as pipe-separated text
    criteria = assessment.result_criteria
    if criteria:
        _criteria_text = " | ".join(criteria) if isinstance(criteria, list) else str(criteria)
        attributes.append(_attr("triggered-criteria", "text", _criteria_text))

    tlp = entity.misp_default_tlp or "tlp:amber"

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {assessment.sector} / {assessment.entity_type}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "1",
            "uuid": event_uuid,
            "Tag": [
                {"name": f'cyberscale:phase="phase-2"'},
                {"name": f'cyberscale:significance-model="{assessment.result_model}"'},
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


def _attr(relation: str, attr_type: str, value: str) -> dict:
    return {
        "object_relation": relation,
        "type": attr_type,
        "value": value,
    }
```

- [ ] **Step 2: Verify the module imports correctly**

Run inside container:
```bash
docker compose exec cyberscale-web python -c "from entity.misp_export import build_misp_event; print('OK')"
```
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add entity/misp_export.py
git commit -m "feat: add MISP JSON export module"
```

---

### Task 2: MISP JSON Download View + URL

**Files:**
- Modify: `entity/views.py` (add view after `assessment_pdf_view`, line ~184)
- Modify: `entity/urls.py` (add URL pattern)

- [ ] **Step 1: Add the MISP JSON view to `entity/views.py`**

Add this import at the top of `entity/views.py`:
```python
import json
```

Add this view after `assessment_pdf_view`:
```python
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
```

- [ ] **Step 2: Add URL pattern to `entity/urls.py`**

Add this line after the PDF URL pattern (line 13):
```python
    path("assess/<int:pk>/misp-json/", views.assessment_misp_json_view, name="assessment_misp_json"),
```

- [ ] **Step 3: Test the endpoint**

```bash
# Using the existing test cookies from earlier, or register fresh:
curl -s -c /tmp/cs2 -b /tmp/cs2 http://localhost:8000/login/ | grep -o 'csrfmiddlewaretoken" value="[^"]*"'
# Then login, navigate to /assess/1/misp-json/ and verify JSON output
docker compose exec cyberscale-web python -c "
import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberscale_web.settings'
django.setup()
from entity.models import Assessment, Entity
from entity.misp_export import build_misp_event
a = Assessment.objects.first()
e = a.entity
event = build_misp_event(a, e)
assert event['Event']['Object'][0]['name'] == 'cyberscale-entity-assessment'
assert 'Tag' in event['Event']
print('MISP export OK:', event['Event']['info'])
"
```
Expected: `MISP export OK: CyberScale entity assessment: energy / electricity_undertaking`

- [ ] **Step 4: Commit**

```bash
git add entity/views.py entity/urls.py
git commit -m "feat: add MISP JSON download endpoint"
```

---

### Task 3: Custom CSS — Institutional Theme

**Files:**
- Create: `static/css/cyberscale.css`

- [ ] **Step 1: Create the CSS file**

Create `static/css/cyberscale.css` with the full institutional theme:

```css
/* CyberScale — Professional/Institutional Theme
   Layered on top of Pico CSS. Navy primary, steel secondary,
   severity-coded accents. */

/* ---- Color tokens ---- */
:root {
  --cs-navy: #1a237e;
  --cs-navy-light: #283593;
  --cs-navy-dark: #0d1452;
  --cs-steel: #455a64;
  --cs-bg: #f8f9fa;
  --cs-surface: #ffffff;
  --cs-border: #dee2e6;
  --cs-significant: #c62828;
  --cs-significant-bg: #fef0f0;
  --cs-not-significant: #2e7d32;
  --cs-not-significant-bg: #f0fdf4;
  --cs-undetermined: #f9a825;
  --cs-undetermined-bg: #fffde7;
  --cs-text: #212529;
  --cs-text-muted: #6c757d;
}

/* ---- Pico overrides ---- */
:root {
  --pico-primary: var(--cs-navy);
  --pico-primary-hover: var(--cs-navy-light);
  --pico-font-size: 15px;
}

body {
  background: var(--cs-bg);
  color: var(--cs-text);
}

/* ---- Navigation ---- */
nav.cs-nav {
  background: var(--cs-navy);
  padding: 0 1.5rem;
  margin-bottom: 0;
}

nav.cs-nav ul {
  margin: 0;
  padding: 0;
}

nav.cs-nav a,
nav.cs-nav a:visited {
  color: rgba(255, 255, 255, 0.85);
  text-decoration: none;
  font-size: 0.9rem;
}

nav.cs-nav a:hover {
  color: #fff;
}

nav.cs-nav .cs-brand {
  font-weight: 700;
  font-size: 1.1rem;
  color: #fff;
  letter-spacing: 0.5px;
}

nav.cs-nav .cs-brand::before {
  content: "◆ ";
  font-size: 0.8em;
  opacity: 0.7;
}

/* ---- Page header ---- */
.cs-page-header {
  margin-bottom: 1.5rem;
}

.cs-page-header h2 {
  color: var(--cs-navy);
  margin-bottom: 0.25rem;
}

.cs-page-header p {
  color: var(--cs-text-muted);
  margin-top: 0;
}

/* ---- Cards ---- */
.cs-card {
  background: var(--cs-surface);
  border: 1px solid var(--cs-border);
  border-radius: 6px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1rem;
}

.cs-card h3 {
  color: var(--cs-navy);
  font-size: 1rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 0;
  margin-bottom: 0.75rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--cs-navy);
}

/* ---- Significance banner ---- */
.cs-sig-banner {
  text-align: center;
  padding: 1.5rem;
  border-radius: 6px;
  margin-bottom: 1.5rem;
}

.cs-sig-banner.significant {
  background: var(--cs-significant-bg);
  border: 2px solid var(--cs-significant);
}

.cs-sig-banner.not-significant {
  background: var(--cs-not-significant-bg);
  border: 2px solid var(--cs-not-significant);
}

.cs-sig-banner.undetermined {
  background: var(--cs-undetermined-bg);
  border: 2px solid var(--cs-undetermined);
}

.cs-sig-label {
  font-size: 1.5rem;
  font-weight: 700;
  display: block;
  margin-bottom: 0.5rem;
}

.cs-sig-banner.significant .cs-sig-label { color: var(--cs-significant); }
.cs-sig-banner.not-significant .cs-sig-label { color: var(--cs-not-significant); }
.cs-sig-banner.undetermined .cs-sig-label { color: var(--cs-undetermined); }

.cs-sig-meta {
  color: var(--cs-text-muted);
  font-size: 0.9rem;
}

/* ---- Badges ---- */
.badge {
  display: inline-block;
  padding: 0.2em 0.65em;
  border-radius: 3px;
  font-weight: 600;
  font-size: 0.8em;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}

.badge-significant,
.badge-likely {
  background: var(--cs-significant);
  color: #fff;
}

.badge-not-significant,
.badge-unlikely {
  background: var(--cs-not-significant);
  color: #fff;
}

.badge-undetermined,
.badge-uncertain {
  background: var(--cs-undetermined);
  color: #000;
}

.badge-model {
  background: var(--cs-navy);
  color: #fff;
  font-size: 0.75em;
}

/* ---- Criteria list ---- */
.cs-criteria-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.cs-criteria-list li {
  padding: 0.4rem 0;
  padding-left: 1.5rem;
  position: relative;
}

.cs-criteria-list li::before {
  content: "▸";
  position: absolute;
  left: 0;
  color: var(--cs-significant);
  font-weight: bold;
}

/* ---- Step indicators ---- */
.cs-steps {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.5rem;
  padding: 0;
  list-style: none;
}

.cs-step {
  flex: 1;
  text-align: center;
  padding: 0.75rem;
  border-bottom: 3px solid var(--cs-border);
  color: var(--cs-text-muted);
  font-size: 0.85rem;
}

.cs-step.active {
  border-bottom-color: var(--cs-navy);
  color: var(--cs-navy);
  font-weight: 600;
}

.cs-step-num {
  display: inline-block;
  width: 1.5rem;
  height: 1.5rem;
  line-height: 1.5rem;
  border-radius: 50%;
  background: var(--cs-border);
  color: var(--cs-text-muted);
  font-size: 0.8rem;
  font-weight: 700;
  margin-right: 0.3rem;
  text-align: center;
}

.cs-step.active .cs-step-num {
  background: var(--cs-navy);
  color: #fff;
}

/* ---- Form sections ---- */
fieldset {
  border: 1px solid var(--cs-border);
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
  background: var(--cs-surface);
}

fieldset legend {
  color: var(--cs-navy);
  font-weight: 600;
  font-size: 0.95rem;
  padding: 0 0.5rem;
}

/* ---- Tables ---- */
table {
  font-size: 0.9rem;
}

thead th {
  background: var(--cs-navy);
  color: #fff;
  font-weight: 600;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}

tbody tr:hover {
  background: #f1f3f5;
}

/* ---- Action bar ---- */
.cs-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.5rem;
  flex-wrap: wrap;
}

.cs-actions a[role="button"] {
  font-size: 0.9rem;
}

/* ---- Profile card ---- */
.cs-profile {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}

.cs-profile-info h3 {
  margin: 0 0 0.25rem 0;
  color: var(--cs-navy);
  border: none;
  text-transform: none;
  letter-spacing: normal;
}

.cs-profile-info p {
  margin: 0;
  color: var(--cs-text-muted);
  font-size: 0.9rem;
}

.cs-profile-icon {
  width: 3.5rem;
  height: 3.5rem;
  border-radius: 50%;
  background: var(--cs-navy);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.3rem;
  font-weight: 700;
}

/* ---- Footer ---- */
footer.cs-footer {
  border-top: 1px solid var(--cs-border);
  margin-top: 3rem;
  padding: 1rem 0;
}

footer.cs-footer small {
  color: var(--cs-text-muted);
}

/* ---- Login/Register card ---- */
.cs-auth-card {
  max-width: 480px;
  margin: 2rem auto;
}

/* ---- Details (sector-specific) ---- */
details {
  border: 1px solid var(--cs-border);
  border-radius: 6px;
  margin-bottom: 1.25rem;
  background: var(--cs-surface);
}

details summary {
  padding: 1rem 1.25rem;
  font-weight: 600;
  color: var(--cs-navy);
  cursor: pointer;
}

details[open] summary {
  border-bottom: 1px solid var(--cs-border);
}

details fieldset {
  border: none;
  margin: 0;
}
```

- [ ] **Step 2: Verify static file is served**

```bash
docker compose exec cyberscale-web python manage.py collectstatic --noinput 2>&1 | tail -3
```
Expected: includes `css/cyberscale.css`

- [ ] **Step 3: Commit**

```bash
git add static/css/cyberscale.css
git commit -m "feat: add institutional CSS theme for CyberScale"
```

---

### Task 4: Rewrite `base.html` — Institutional Nav + CSS

**Files:**
- Rewrite: `templates/base.html`

- [ ] **Step 1: Replace `templates/base.html` with the institutional layout**

```html
{% load static %}
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}CyberScale{% endblock %}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <link rel="stylesheet" href="{% static 'css/cyberscale.css' %}">
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  {% block extra_head %}{% endblock %}
</head>
<body>
  <nav class="cs-nav container-fluid">
    <ul>
      <li><a href="/" class="cs-brand">CyberScale</a></li>
    </ul>
    <ul>
      {% if user.is_authenticated %}
        <li><a href="{% url 'dashboard' %}">Dashboard</a></li>
        <li><a href="{% url 'assessment_form' %}">New Assessment</a></li>
        <li><a href="{% url 'logout' %}">Logout ({{ user.username }})</a></li>
      {% else %}
        <li><a href="{% url 'login' %}">Login</a></li>
        <li><a href="{% url 'register' %}">Register</a></li>
      {% endif %}
    </ul>
  </nav>

  <main class="container">
    {% if messages %}
      {% for message in messages %}
        <article>{{ message }}</article>
      {% endfor %}
    {% endif %}

    {% block content %}{% endblock %}
  </main>

  <footer class="cs-footer container">
    <small>CyberScale v1.0.0 — Assessment is advisory. Notification decision remains the entity's responsibility.</small>
  </footer>
</body>
</html>
```

- [ ] **Step 2: Verify page loads**

```bash
curl -s http://localhost:8000/login/ | grep "cyberscale.css"
```
Expected: line containing `cyberscale.css`

- [ ] **Step 3: Commit**

```bash
git add templates/base.html
git commit -m "feat: institutional nav and theme in base template"
```

---

### Task 5: Rewrite Login + Register Templates

**Files:**
- Rewrite: `templates/entity/login.html`
- Rewrite: `templates/entity/register.html`

- [ ] **Step 1: Replace `templates/entity/login.html`**

```html
{% extends "base.html" %}
{% block title %}Login — CyberScale{% endblock %}

{% block content %}
<div class="cs-auth-card">
  <article class="cs-card">
    <h3>Login</h3>

    <form method="post">
      {% csrf_token %}

      {% if form.errors %}
        <p style="color: var(--cs-significant);">Invalid username or password.</p>
      {% endif %}

      <label>Username {{ form.username }}</label>
      <label>Password {{ form.password }}</label>

      <button type="submit">Login</button>
    </form>

    <p><small>No account? <a href="{% url 'register' %}">Register your entity</a></small></p>
  </article>
</div>
{% endblock %}
```

- [ ] **Step 2: Replace `templates/entity/register.html`**

```html
{% extends "base.html" %}
{% block title %}Register — CyberScale{% endblock %}

{% block content %}
<div class="cs-auth-card" style="max-width: 600px;">
  <article class="cs-card">
    <h3>Entity Registration</h3>

    <form method="post">
      {% csrf_token %}

      <fieldset>
        <legend>Account</legend>
        <label>Username {{ form.username }}</label>
        {% if form.username.errors %}<small style="color: var(--cs-significant);">{{ form.username.errors.0 }}</small>{% endif %}
        <label>Password {{ form.password1 }}</label>
        {% if form.password1.errors %}<small style="color: var(--cs-significant);">{{ form.password1.errors.0 }}</small>{% endif %}
        <label>Confirm password {{ form.password2 }}</label>
        {% if form.password2.errors %}<small style="color: var(--cs-significant);">{{ form.password2.errors.0 }}</small>{% endif %}
      </fieldset>

      <fieldset>
        <legend>Entity Profile</legend>
        <label>Organisation name {{ form.organisation_name }}</label>
        {% if form.organisation_name.errors %}<small style="color: var(--cs-significant);">{{ form.organisation_name.errors.0 }}</small>{% endif %}

        <label>Sector
          <select name="sector" id="id_sector"
                  hx-get="{% url 'htmx_entity_types' %}"
                  hx-target="#id_entity_type"
                  hx-trigger="change"
                  hx-swap="innerHTML">
            {% for value, label in form.sector.field.choices %}
              <option value="{{ value }}" {% if value == form.sector.value %}selected{% endif %}>{{ label }}</option>
            {% endfor %}
          </select>
        </label>
        {% if form.sector.errors %}<small style="color: var(--cs-significant);">{{ form.sector.errors.0 }}</small>{% endif %}

        <label>Entity type
          <select name="entity_type" id="id_entity_type">
            <option value="">— Select sector first —</option>
          </select>
        </label>
        {% if form.entity_type.errors %}<small style="color: var(--cs-significant);">{{ form.entity_type.errors.0 }}</small>{% endif %}

        <label>Member state established {{ form.ms_established }}</label>
        {% if form.ms_established.errors %}<small style="color: var(--cs-significant);">{{ form.ms_established.errors.0 }}</small>{% endif %}
      </fieldset>

      <button type="submit">Register</button>
    </form>

    <p><small>Already have an account? <a href="{% url 'login' %}">Login</a></small></p>
  </article>
</div>
{% endblock %}
```

Key changes:
- Removed `hx-include="[name='sector']"` — not needed since `hx-get` reads the select value directly
- Added `hx-swap="innerHTML"` for correct HTMX behavior
- Removed the JS `entityTypesBySector` block (HTMX handles it server-side)
- Applied `cs-auth-card` and `cs-card` classes

- [ ] **Step 3: Test HTMX sector filtering**

Open http://localhost:8000/register/ in browser, select "Energy" in sector dropdown. Entity type dropdown should populate with electricity_undertaking, distribution_system_operator, etc. via HTMX.

- [ ] **Step 4: Commit**

```bash
git add templates/entity/login.html templates/entity/register.html
git commit -m "feat: institutional login + register with HTMX sector filtering"
```

---

### Task 6: Rewrite Dashboard Template

**Files:**
- Rewrite: `templates/entity/dashboard.html`

- [ ] **Step 1: Replace `templates/entity/dashboard.html`**

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
          <th>Significance</th>
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
            {% if a.result_significance_label == "SIGNIFICANT" or a.result_significance_label == "LIKELY" %}
              <span class="badge badge-significant">{{ a.result_significance_label }}</span>
            {% elif a.result_significance_label == "NOT SIGNIFICANT" or a.result_significance_label == "UNLIKELY" %}
              <span class="badge badge-not-significant">{{ a.result_significance_label }}</span>
            {% else %}
              <span class="badge badge-undetermined">{{ a.result_significance_label }}</span>
            {% endif %}
          </td>
          <td><span class="badge badge-model">{{ a.result_model }}</span></td>
          <td>
            <a href="{% url 'assessment_result' a.pk %}">View</a>
            &middot; <a href="{% url 'assessment_pdf' a.pk %}">PDF</a>
            &middot; <a href="{% url 'assessment_misp_json' a.pk %}">MISP</a>
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

- [ ] **Step 2: Verify dashboard loads**

```bash
curl -s -c /tmp/cs_cookies -b /tmp/cs_cookies http://localhost:8000/ | grep "cs-profile"
```
Expected: HTML containing `cs-profile`

- [ ] **Step 3: Commit**

```bash
git add templates/entity/dashboard.html
git commit -m "feat: institutional dashboard with profile card and MISP links"
```

---

### Task 7: Rewrite Assessment Form Template

**Files:**
- Rewrite: `templates/entity/assessment_form.html`

- [ ] **Step 1: Replace `templates/entity/assessment_form.html`**

```html
{% extends "base.html" %}
{% block title %}New Assessment — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>Incident Assessment</h2>
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

  <button type="submit">Run Assessment</button>
</form>
{% endblock %}
```

- [ ] **Step 2: Commit**

```bash
git add templates/entity/assessment_form.html
git commit -m "feat: institutional assessment form with step indicators"
```

---

### Task 8: Rewrite Assessment Result Template

**Files:**
- Rewrite: `templates/entity/assessment_result.html`

- [ ] **Step 1: Replace `templates/entity/assessment_result.html`**

```html
{% extends "base.html" %}
{% block title %}Assessment #{{ assessment.pk }} — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>Assessment #{{ assessment.pk }}</h2>
  <p>{{ entity.organisation_name }} — {{ assessment.created_at|date:"Y-m-d H:i" }} UTC</p>
</div>

{# Significance banner #}
{% if assessment.result_significance_label == "SIGNIFICANT" or assessment.result_significance_label == "LIKELY" %}
  <div class="cs-sig-banner significant">
{% elif assessment.result_significance_label == "NOT SIGNIFICANT" or assessment.result_significance_label == "UNLIKELY" %}
  <div class="cs-sig-banner not-significant">
{% else %}
  <div class="cs-sig-banner undetermined">
{% endif %}
    <span class="cs-sig-label">{{ assessment.result_significance_label }}</span>
    <span class="cs-sig-meta">
      {% if assessment.result_framework %}{{ assessment.result_framework }}{% endif %}
      {% if assessment.result_competent_authority %} — {{ assessment.result_competent_authority }}{% endif %}
      &middot; {{ assessment.result_model }}
    </span>
  </div>

{# Two-column: Criteria + Early Warning #}
<div class="grid">
  {% if assessment.result_criteria %}
  <div class="cs-card">
    <h3>Triggered Criteria</h3>
    <ul class="cs-criteria-list">
      {% for criterion in assessment.result_criteria %}
        <li>{{ criterion }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  {% if assessment.result_early_warning %}
  <div class="cs-card">
    <h3>Early Warning</h3>
    {% with ew=assessment.result_early_warning %}
      {% if ew.recommended %}
        <p><span class="badge badge-significant">RECOMMENDED</span></p>
        <p><strong>Deadline:</strong> {{ ew.deadline }} from awareness</p>
        {% if ew.required_content %}
          <p><strong>Required content:</strong></p>
          <ul>
            {% for item in ew.required_content %}
              <li>{{ item }}</li>
            {% endfor %}
          </ul>
        {% endif %}
      {% else %}
        <p><span class="badge badge-not-significant">NOT RECOMMENDED</span></p>
      {% endif %}
      {% if ew.next_step %}
        <p style="margin-top: 0.75rem;"><strong>Next steps:</strong> {{ ew.next_step }}</p>
      {% endif %}
    {% endwith %}
  </div>
  {% endif %}
</div>

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

{# Description #}
<div class="cs-card">
  <h3>Incident Description</h3>
  <p>{{ assessment.description }}</p>
</div>

{# Actions #}
<div class="cs-actions">
  <a href="{% url 'assessment_pdf' assessment.pk %}" role="button">Download PDF</a>
  <a href="{% url 'assessment_misp_json' assessment.pk %}" role="button" class="secondary">Download MISP JSON</a>
  <a href="{% url 'dashboard' %}" role="button" class="outline">Back to Dashboard</a>
</div>

<br>
<small style="color: var(--cs-text-muted);">Generated by CyberScale v1.0.0. Assessment is advisory — notification decision remains the entity's responsibility.</small>
{% endblock %}
```

- [ ] **Step 2: Commit**

```bash
git add templates/entity/assessment_result.html
git commit -m "feat: institutional result page with MISP JSON download"
```

---

### Task 9: Update PDF Template Colors

**Files:**
- Modify: `templates/entity/assessment_pdf.html`

- [ ] **Step 1: Update PDF template to match institutional theme**

Replace the `<style>` section (lines 5-25) in `templates/entity/assessment_pdf.html` with:

```css
    @page { size: A4; margin: 2cm; }
    body { font-family: sans-serif; font-size: 11pt; color: #212529; line-height: 1.5; }
    h1 { font-size: 18pt; border-bottom: 3px solid #1a237e; padding-bottom: 8px; color: #1a237e; margin-bottom: 0.25rem; }
    h2 { font-size: 13pt; color: #1a237e; margin-top: 1.5em; border-bottom: 1px solid #dee2e6; padding-bottom: 4px; text-transform: uppercase; letter-spacing: 0.3px; }
    .header-meta { color: #6c757d; font-size: 10pt; }
    .sig-box { border: 2px solid #333; padding: 14px; margin: 16px 0; text-align: center; border-radius: 4px; }
    .sig-significant { border-color: #c62828; background: #fef0f0; }
    .sig-not-significant { border-color: #2e7d32; background: #f0fdf4; }
    .sig-undetermined { border-color: #f9a825; background: #fffde7; }
    .sig-label { font-size: 16pt; font-weight: bold; }
    .sig-significant .sig-label { color: #c62828; }
    .sig-not-significant .sig-label { color: #2e7d32; }
    .sig-undetermined .sig-label { color: #f9a825; }
    table { width: 100%; border-collapse: collapse; margin: 8px 0; }
    td, th { border: 1px solid #dee2e6; padding: 6px 10px; text-align: left; }
    th { background: #1a237e; color: #fff; font-size: 0.9em; }
    .criteria-list { list-style: none; padding: 0; }
    .criteria-list li { padding: 4px 0; padding-left: 1em; }
    .criteria-list li::before { content: "▸ "; color: #c62828; font-weight: bold; }
    .footer { margin-top: 2em; border-top: 1px solid #dee2e6; padding-top: 8px; font-size: 9pt; color: #6c757d; }
    .ew-recommended { color: #c62828; font-weight: bold; }
    .ew-not-recommended { color: #2e7d32; font-weight: bold; }
```

- [ ] **Step 2: Commit**

```bash
git add templates/entity/assessment_pdf.html
git commit -m "feat: align PDF colors with institutional web theme"
```

---

### Task 10: End-to-End Verification

- [ ] **Step 1: Rebuild and restart containers**

```bash
docker compose exec cyberscale-web python manage.py collectstatic --noinput
```

- [ ] **Step 2: Test registration with HTMX sector filtering**

Open http://localhost:8000/register/, select a sector, verify entity types populate via HTMX.

- [ ] **Step 3: Test assessment + result page**

Create a new assessment, verify:
- Step indicators visible
- Significance banner renders with correct color
- Triggered criteria in card layout
- Both PDF and MISP JSON download buttons present

- [ ] **Step 4: Test MISP JSON download**

```bash
docker compose exec cyberscale-web python -c "
import os, django, json
os.environ['DJANGO_SETTINGS_MODULE'] = 'cyberscale_web.settings'
django.setup()
from entity.models import Assessment
from entity.misp_export import build_misp_event
a = Assessment.objects.first()
event = build_misp_event(a, a.entity)
print(json.dumps(event, indent=2)[:500])
assert event['Event']['Object'][0]['name'] == 'cyberscale-entity-assessment'
assert len(event['Event']['Tag']) == 4
print('\\nAll checks passed.')
"
```

- [ ] **Step 5: Test PDF download**

```bash
curl -s -c /tmp/cs_cookies -b /tmp/cs_cookies http://localhost:8000/assess/1/pdf/ -o /tmp/cs_test2.pdf -w "%{http_code}"
```
Expected: `200`

- [ ] **Step 6: Commit verification note**

No code changes — just verification. All tasks complete.
