# Art. 27 Entity Registration & MISP Entity Profile — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Entity with Art. 27 NIS2 registration fields, build a profile editing UI, introduce a `cyberscale-entity-profile` MISP object as a standalone event, link assessment events to profile via object references, move all MISP push to admin-only actions, add local MISP to Docker Compose, and test end-to-end against a real MISP instance.

**Architecture:** Incremental extension of the existing Entity model with 11 new fields. Profile editing via a new Django form/view. MISP profile built by a new `misp_profile_export.py` module. Admin actions for push (profile first, then assessments). Assessment events include object references to the profile event UUID. Docker Compose gains MISP + MySQL + Redis containers.

**Tech Stack:** Django 5.x, PyMISP >=2.4, PostgreSQL 16, MISP Docker (ghcr.io/misp/misp-docker), Pico CSS, HTMX

---

## File Structure

| File | Responsibility |
|---|---|
| `entity/models.py` | 11 new Entity fields, new Submission target choice, `misp_profile_event_uuid` |
| `entity/migrations/0006_art27_profile.py` | Migration for new fields |
| `entity/forms.py` | New `EntityProfileForm` with CIDR validation |
| `entity/views.py` | Add `profile_edit_view`, remove `assessment_misp_push_view`, update `impact_fields_view` for MS filtering |
| `entity/urls.py` | Add `/profile/edit/`, remove `/assess/<pk>/misp-push/` |
| `entity/misp_profile_export.py` | New — `build_misp_profile_event()` builder |
| `entity/misp_export.py` | Add `profile_event_uuid` param + ObjectReference to builders |
| `entity/misp_push.py` | Add `update_event()` support, handle ObjectReference in `_dict_to_misp_event` |
| `entity/admin.py` | Fieldsets, "Push profile to MISP" + "Push to MISP" actions, readonly fields |
| `templates/entity/profile_edit.html` | New — profile edit form template |
| `templates/entity/dashboard.html` | Add "Edit Profile" button |
| `templates/entity/assessment_result.html` | Remove "Push to MISP" button |
| `templates/entity/partials/impact_fields.html` | MS affected filtering |
| `docker-compose.yml` | Add MISP + MySQL + Redis containers |
| `entity/tests/test_profile.py` | New — profile form, validation, MS filtering tests |
| `entity/tests/test_misp_push.py` | Adapt for admin-only push, add profile push + object reference tests |
| `entity/tests/test_misp_integration.py` | New — real MISP integration tests |

---

### Task 1: Entity Model — Art. 27 Fields

**Files:**
- Modify: `entity/models.py:7-27` (Entity class)
- Modify: `entity/models.py:129-152` (Submission class)
- Create: `entity/migrations/0006_art27_profile.py`
- Test: `entity/tests/test_models.py`

- [ ] **Step 1: Write failing test for new Entity fields**

In `entity/tests/test_models.py`, add:

```python
class EntityArt27FieldsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("art27user", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Art27 Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            address="42 Rue du Code, L-1234 Luxembourg",
            contact_email="info@art27corp.lu",
            contact_phone="+352 123 456",
            responsible_person_name="Alice Manager",
            responsible_person_email="alice@art27corp.lu",
            technical_contact_name="Bob Tech",
            technical_contact_email="bob@art27corp.lu",
            technical_contact_phone="+352 789 012",
            ip_ranges=["192.168.1.0/24", "10.0.0.0/8"],
            ms_services=["LU", "BE", "DE"],
        )

    def test_art27_fields_persisted(self):
        e = Entity.objects.get(pk=self.entity.pk)
        assert e.address == "42 Rue du Code, L-1234 Luxembourg"
        assert e.contact_email == "info@art27corp.lu"
        assert e.contact_phone == "+352 123 456"
        assert e.responsible_person_name == "Alice Manager"
        assert e.responsible_person_email == "alice@art27corp.lu"
        assert e.technical_contact_name == "Bob Tech"
        assert e.technical_contact_email == "bob@art27corp.lu"
        assert e.technical_contact_phone == "+352 789 012"
        assert e.ip_ranges == ["192.168.1.0/24", "10.0.0.0/8"]
        assert e.ms_services == ["LU", "BE", "DE"]
        assert e.misp_profile_event_uuid == ""

    def test_art27_fields_blank_defaults(self):
        user2 = User.objects.create_user("minimal", password="testpass123")
        e = Entity.objects.create(
            user=user2, organisation_name="Minimal", sector="energy",
            entity_type="electricity_undertaking", ms_established="LU",
        )
        assert e.address == ""
        assert e.contact_email == ""
        assert e.ip_ranges == []
        assert e.ms_services == []
        assert e.misp_profile_event_uuid == ""


class SubmissionProfileTargetTest(TestCase):
    def test_misp_profile_push_target_valid(self):
        user = User.objects.create_user("subtest", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="Sub Corp", sector="energy",
            entity_type="electricity_undertaking", ms_established="LU",
        )
        a = Assessment.objects.create(
            entity=entity, status="completed", description="Test",
            sector="energy", entity_type="electricity_undertaking",
        )
        sub = Submission.objects.create(
            assessment=a, target="misp_profile_push", status="success",
        )
        assert sub.target == "misp_profile_push"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_models.py::EntityArt27FieldsTest -v`
Expected: FAIL — fields do not exist on Entity model

- [ ] **Step 3: Add fields to Entity model**

In `entity/models.py`, add after line 20 (`misp_default_tlp`):

```python
    # Art. 27 — Address & contact
    address = models.TextField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)

    # Art. 27 — Responsible person (legal/management)
    responsible_person_name = models.CharField(max_length=255, blank=True)
    responsible_person_email = models.EmailField(blank=True)

    # Art. 27 — Technical contact (operational/incident response)
    technical_contact_name = models.CharField(max_length=255, blank=True)
    technical_contact_email = models.EmailField(blank=True)
    technical_contact_phone = models.CharField(max_length=50, blank=True)

    # Art. 27 — IP ranges (validated CIDR, stored as JSON list)
    ip_ranges = models.JSONField(default=list, blank=True)

    # Art. 27 — MS where services are provided
    ms_services = models.JSONField(default=list, blank=True)

    # MISP profile tracking
    misp_profile_event_uuid = models.CharField(max_length=36, blank=True)
```

In `Submission.TARGET_CHOICES`, add after `("misp_push", "MISP Push")`:

```python
        ("misp_profile_push", "MISP Profile Push"),
```

- [ ] **Step 4: Generate and apply migration**

Run: `docker compose exec cyberscale-web python manage.py makemigrations entity --name art27_profile`
Run: `docker compose exec cyberscale-web python manage.py migrate`

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_models.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add entity/models.py entity/migrations/0006_art27_profile.py entity/tests/test_models.py
git commit -m "feat: add Art. 27 entity profile fields and migration"
```

---

### Task 2: Profile Edit Form with CIDR Validation

**Files:**
- Modify: `entity/forms.py`
- Create: `entity/tests/test_profile.py`

- [ ] **Step 1: Write failing tests for EntityProfileForm**

Create `entity/tests/test_profile.py`:

```python
"""Tests for entity profile editing and CIDR validation."""

import ipaddress

from django.contrib.auth.models import User
from django.test import TestCase

from entity.forms import EntityProfileForm
from entity.models import Entity


class EntityProfileFormTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("profuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Profile Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )

    def test_form_loads_with_instance(self):
        form = EntityProfileForm(instance=self.entity)
        assert "organisation_name" in form.fields
        assert "address" in form.fields
        assert "ip_ranges" in form.fields
        assert "ms_services" in form.fields

    def test_valid_cidr_accepted(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "192.168.1.0/24\n10.0.0.0/8\n2001:db8::/32",
                "ms_services": ["LU", "BE"],
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ip_ranges == ["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]

    def test_invalid_cidr_rejected(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "192.168.1.0/24\nnot-a-cidr\n999.999.999.999/99",
            },
        )
        assert not form.is_valid()
        assert "ip_ranges" in form.errors

    def test_empty_ip_ranges_valid(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={"organisation_name": "Profile Corp", "ip_ranges": ""},
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ip_ranges == []

    def test_ms_services_saved_as_list(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "",
                "ms_services": ["LU", "DE", "FR"],
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ms_services == ["LU", "DE", "FR"]

    def test_all_art27_fields_saved(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Updated Corp",
                "address": "1 Rue NIS2",
                "contact_email": "sec@corp.lu",
                "contact_phone": "+352 111",
                "responsible_person_name": "Alice",
                "responsible_person_email": "alice@corp.lu",
                "technical_contact_name": "Bob",
                "technical_contact_email": "bob@corp.lu",
                "technical_contact_phone": "+352 222",
                "ip_ranges": "10.0.0.0/8",
                "ms_services": ["LU"],
                "misp_instance_url": "",
                "misp_api_key": "",
                "misp_default_tlp": "tlp:amber",
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.organisation_name == "Updated Corp"
        assert entity.address == "1 Rue NIS2"
        assert entity.technical_contact_name == "Bob"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py -v`
Expected: FAIL — `EntityProfileForm` does not exist

- [ ] **Step 3: Implement EntityProfileForm**

In `entity/forms.py`, add at the end:

```python
import ipaddress as _ipaddress


class EntityProfileForm(forms.ModelForm):
    """Entity profile editing form with Art. 27 fields."""

    ip_ranges = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "One CIDR per line, e.g.:\n192.168.1.0/24\n10.0.0.0/8"}),
        required=False,
        help_text="IP address ranges in CIDR notation, one per line.",
    )
    ms_services = forms.MultipleChoiceField(
        choices=[(code, label) for code, label in MS_CHOICES if code],
        widget=forms.CheckboxSelectMultiple,
        required=False,
        help_text="Member states where this entity provides services.",
    )

    class Meta:
        model = Entity
        fields = [
            "organisation_name", "address",
            "contact_email", "contact_phone",
            "responsible_person_name", "responsible_person_email",
            "technical_contact_name", "technical_contact_email", "technical_contact_phone",
            "ip_ranges", "ms_services",
            "misp_instance_url", "misp_api_key", "misp_default_tlp",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-populate ip_ranges textarea from JSON list
        if self.instance and self.instance.ip_ranges:
            self.initial["ip_ranges"] = "\n".join(self.instance.ip_ranges)

    def clean_ip_ranges(self):
        raw = self.cleaned_data.get("ip_ranges", "")
        if not raw.strip():
            return []
        ranges = []
        errors = []
        for i, line in enumerate(raw.strip().split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                net = _ipaddress.ip_network(line, strict=False)
                ranges.append(str(net))
            except ValueError:
                errors.append(f"Line {i}: '{line}' is not a valid CIDR")
        if errors:
            raise forms.ValidationError(errors)
        return ranges
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/forms.py entity/tests/test_profile.py
git commit -m "feat: add EntityProfileForm with CIDR validation"
```

---

### Task 3: Profile Edit View, URL, and Template

**Files:**
- Modify: `entity/views.py`
- Modify: `entity/urls.py`
- Create: `templates/entity/profile_edit.html`
- Modify: `templates/entity/dashboard.html`
- Test: `entity/tests/test_profile.py`

- [ ] **Step 1: Write failing tests for profile edit view**

Append to `entity/tests/test_profile.py`:

```python
from django.test import Client


class ProfileEditViewTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("edituser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Edit Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )
        self.client = Client()
        self.client.login(username="edituser", password="testpass123")

    def test_profile_edit_loads(self):
        resp = self.client.get("/profile/edit/")
        assert resp.status_code == 200
        assert b"Edit Corp" in resp.content
        assert b"Organisation" in resp.content

    def test_profile_edit_requires_login(self):
        c = Client()
        resp = c.get("/profile/edit/")
        assert resp.status_code == 302
        assert "/login/" in resp.url

    def test_profile_edit_saves(self):
        resp = self.client.post("/profile/edit/", {
            "organisation_name": "Updated Corp",
            "address": "1 Rue NIS2",
            "contact_email": "sec@corp.lu",
            "ip_ranges": "10.0.0.0/8",
            "ms_services": ["LU", "BE"],
            "misp_default_tlp": "tlp:amber",
        })
        assert resp.status_code == 302
        self.entity.refresh_from_db()
        assert self.entity.organisation_name == "Updated Corp"
        assert self.entity.address == "1 Rue NIS2"
        assert self.entity.ip_ranges == ["10.0.0.0/8"]
        assert self.entity.ms_services == ["LU", "BE"]

    def test_dashboard_has_edit_profile_link(self):
        resp = self.client.get("/")
        assert b"/profile/edit/" in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py::ProfileEditViewTest -v`
Expected: FAIL — 404 on `/profile/edit/`

- [ ] **Step 3: Add profile_edit_view to views.py**

In `entity/views.py`, add after `assessment_result_view` (after line 288):

```python
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
```

- [ ] **Step 4: Add URL route**

In `entity/urls.py`, add after the `logout` path (line 9):

```python
    path("profile/edit/", views.profile_edit_view, name="profile_edit"),
```

- [ ] **Step 5: Create profile edit template**

Create `templates/entity/profile_edit.html`:

```html
{% extends "base.html" %}
{% block title %}Edit Profile — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>Edit Entity Profile</h2>
  <p>{{ entity.organisation_name }} — MS established: {{ entity.ms_established }}</p>
</div>

<form method="post">
  {% csrf_token %}

  {% if form.errors %}
    <div class="cs-card" style="border-left: 3px solid var(--cs-significant);">
      <p><strong>Please correct the errors below:</strong></p>
      {{ form.errors }}
    </div>
  {% endif %}

  <fieldset>
    <legend>Organisation</legend>
    <label>Organisation name {{ form.organisation_name }}</label>
    <label>Address {{ form.address }}</label>
  </fieldset>

  <fieldset>
    <legend>General Contact</legend>
    <div class="grid">
      <label>Email {{ form.contact_email }}</label>
      <label>Phone {{ form.contact_phone }}</label>
    </div>
  </fieldset>

  <fieldset>
    <legend>Responsible Person</legend>
    <div class="grid">
      <label>Name {{ form.responsible_person_name }}</label>
      <label>Email {{ form.responsible_person_email }}</label>
    </div>
  </fieldset>

  <fieldset>
    <legend>Technical Contact</legend>
    <div class="grid">
      <label>Name {{ form.technical_contact_name }}</label>
      <label>Email {{ form.technical_contact_email }}</label>
    </div>
    <label>Phone {{ form.technical_contact_phone }}</label>
  </fieldset>

  <fieldset>
    <legend>Service Provision</legend>
    <label>Member states where services are provided</label>
    <div class="cs-checkbox-grid">
      {{ form.ms_services }}
    </div>
  </fieldset>

  <fieldset>
    <legend>IP Ranges</legend>
    <label>IP address ranges (CIDR notation, one per line) {{ form.ip_ranges }}</label>
  </fieldset>

  <fieldset>
    <legend>MISP Settings</legend>
    <label>MISP instance URL {{ form.misp_instance_url }}</label>
    <label>API key {{ form.misp_api_key }}</label>
    <label>Default TLP {{ form.misp_default_tlp }}</label>
  </fieldset>

  <div class="cs-actions">
    <button type="submit">Save Profile</button>
    <a href="{% url 'dashboard' %}" role="button" class="outline">Cancel</a>
  </div>
</form>
{% endblock %}
```

- [ ] **Step 6: Add "Edit Profile" button to dashboard**

In `templates/entity/dashboard.html`, after line 11 (`</div>` closing `cs-profile`), add:

```html
<a href="{% url 'profile_edit' %}" role="button" class="outline" style="margin-top: 0.5rem; font-size: 0.85rem;">Edit Profile</a>
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py -v`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add entity/views.py entity/urls.py templates/entity/profile_edit.html templates/entity/dashboard.html entity/tests/test_profile.py
git commit -m "feat: add entity profile edit view with Art. 27 fields"
```

---

### Task 4: MISP Entity Profile Object Builder

**Files:**
- Create: `entity/misp_profile_export.py`
- Test: `entity/tests/test_profile.py`

- [ ] **Step 1: Write failing tests for profile MISP export**

Append to `entity/tests/test_profile.py`:

```python
from entity.models import EntityType


class MISPProfileExportTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("mispprof", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="MISP Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            address="42 Rue du Code",
            contact_email="info@mispcorp.lu",
            contact_phone="+352 123",
            responsible_person_name="Alice",
            responsible_person_email="alice@mispcorp.lu",
            technical_contact_name="Bob",
            technical_contact_email="bob@mispcorp.lu",
            technical_contact_phone="+352 456",
            ip_ranges=["192.168.1.0/24", "10.0.0.0/8"],
            ms_services=["LU", "BE"],
            misp_default_tlp="tlp:green",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        EntityType.objects.create(
            entity=self.entity, sector="health", entity_type="healthcare_provider",
        )

    def test_build_profile_event_structure(self):
        from entity.misp_profile_export import build_misp_profile_event

        event = build_misp_profile_event(self.entity)
        assert "Event" in event
        evt = event["Event"]
        assert "CyberScale entity profile: MISP Corp" == evt["info"]
        assert evt["threat_level_id"] == "4"
        assert len(evt["Object"]) == 1

        obj = evt["Object"][0]
        assert obj["name"] == "cyberscale-entity-profile"

        attrs = {a["object_relation"]: a["value"] for a in obj["Attribute"] if a["object_relation"] not in ("ip-range", "sector", "entity-type")}
        assert attrs["organisation-name"] == "MISP Corp"
        assert attrs["address"] == "42 Rue du Code"
        assert attrs["contact-email"] == "info@mispcorp.lu"
        assert attrs["responsible-person-name"] == "Alice"
        assert attrs["technical-contact-name"] == "Bob"
        assert attrs["ms-established"] == "LU"
        assert attrs["ms-services"] == "LU, BE"

    def test_build_profile_event_ip_ranges(self):
        from entity.misp_profile_export import build_misp_profile_event

        event = build_misp_profile_event(self.entity)
        obj = event["Event"]["Object"][0]
        ip_attrs = [a for a in obj["Attribute"] if a["object_relation"] == "ip-range"]
        assert len(ip_attrs) == 2
        assert ip_attrs[0]["value"] == "192.168.1.0/24"
        assert ip_attrs[0]["type"] == "ip-src"

    def test_build_profile_event_entity_types(self):
        from entity.misp_profile_export import build_misp_profile_event

        event = build_misp_profile_event(self.entity)
        obj = event["Event"]["Object"][0]
        sector_attrs = [a for a in obj["Attribute"] if a["object_relation"] == "sector"]
        type_attrs = [a for a in obj["Attribute"] if a["object_relation"] == "entity-type"]
        assert len(sector_attrs) == 2
        assert len(type_attrs) == 2

    def test_build_profile_event_tags(self):
        from entity.misp_profile_export import build_misp_profile_event

        event = build_misp_profile_event(self.entity)
        tag_names = [t["name"] for t in event["Event"]["Tag"]]
        assert 'cyberscale:type="entity-profile"' in tag_names
        assert "tlp:green" in tag_names

    def test_build_profile_event_uuid(self):
        from entity.misp_profile_export import build_misp_profile_event

        self.entity.misp_profile_event_uuid = "fixed-uuid-123"
        event = build_misp_profile_event(self.entity)
        assert event["Event"]["uuid"] == "fixed-uuid-123"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py::MISPProfileExportTest -v`
Expected: FAIL — module does not exist

- [ ] **Step 3: Implement misp_profile_export.py**

Create `entity/misp_profile_export.py`:

```python
"""MISP JSON export for CyberScale entity profiles (Art. 27)."""

from __future__ import annotations

import uuid


def build_misp_profile_event(entity) -> dict:
    """Build a MISP event dict for an entity profile.

    Creates a standalone event with a single cyberscale-entity-profile object
    containing all Art. 27 registration fields.
    """
    event_uuid = entity.misp_profile_event_uuid or str(uuid.uuid4())
    tlp = entity.misp_default_tlp or "tlp:amber"

    attributes = [
        _attr("organisation-name", "text", entity.organisation_name),
        _attr("address", "text", entity.address),
        _attr("contact-email", "email-src", entity.contact_email),
        _attr("contact-phone", "phone-number", entity.contact_phone),
        _attr("responsible-person-name", "text", entity.responsible_person_name),
        _attr("responsible-person-email", "email-src", entity.responsible_person_email),
        _attr("technical-contact-name", "text", entity.technical_contact_name),
        _attr("technical-contact-email", "email-src", entity.technical_contact_email),
        _attr("technical-contact-phone", "phone-number", entity.technical_contact_phone),
        _attr("ms-established", "text", entity.ms_established),
        _attr("ms-services", "text", ", ".join(entity.ms_services or [])),
    ]

    for cidr in (entity.ip_ranges or []):
        attributes.append(_attr("ip-range", "ip-src", cidr))

    for et in entity.entity_types.all():
        attributes.append(_attr("sector", "text", et.sector))
        attributes.append(_attr("entity-type", "text", et.entity_type))

    return {
        "Event": {
            "info": f"CyberScale entity profile: {entity.organisation_name}",
            "threat_level_id": "4",
            "analysis": "2",
            "distribution": "1",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:type="entity-profile"'},
                {"name": tlp},
            ],
            "Object": [
                {
                    "name": "cyberscale-entity-profile",
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py::MISPProfileExportTest -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/misp_profile_export.py entity/tests/test_profile.py
git commit -m "feat: add cyberscale-entity-profile MISP object builder"
```

---

### Task 5: Object Reference Linking — Assessment References Profile

**Files:**
- Modify: `entity/misp_export.py`
- Modify: `entity/misp_push.py`
- Test: `entity/tests/test_misp_push.py`

- [ ] **Step 1: Write failing tests for object references**

In `entity/tests/test_misp_push.py`, add:

```python
class ObjectReferenceTest(TestCase):
    """Tests for assessment→profile object references."""

    def test_global_event_includes_reference(self):
        from entity.misp_export import build_misp_event_global

        user = User.objects.create_user("refuser", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="Ref Corp", sector="energy",
            entity_type="electricity_undertaking", ms_established="LU",
            misp_profile_event_uuid="profile-uuid-abc",
        )
        assessment = Assessment.objects.create(
            entity=entity, status="completed",
            description="Test", sector="energy", entity_type="electricity_undertaking",
            misp_event_uuid="event-uuid-xyz",
            result_significance_label="SIGNIFICANT",
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": False},
                "triggered_criteria": [],
            }],
        )

        event = build_misp_event_global(assessment, entity, profile_event_uuid="profile-uuid-abc")
        obj = event["Event"]["Object"][0]
        assert "ObjectReference" in obj
        assert obj["ObjectReference"][0]["referenced_uuid"] == "profile-uuid-abc"
        assert obj["ObjectReference"][0]["relationship_type"] == "belongs-to"

    def test_global_event_no_reference_without_uuid(self):
        from entity.misp_export import build_misp_event_global

        user = User.objects.create_user("noref", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="NoRef Corp", sector="energy",
            entity_type="electricity_undertaking", ms_established="LU",
        )
        assessment = Assessment.objects.create(
            entity=entity, status="completed",
            description="Test", sector="energy", entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": False},
                "triggered_criteria": [],
            }],
        )

        event = build_misp_event_global(assessment, entity)
        obj = event["Event"]["Object"][0]
        assert "ObjectReference" not in obj

    def test_single_event_includes_reference(self):
        from entity.misp_export import build_misp_event

        user = User.objects.create_user("singleref", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="Single Corp", sector="energy",
            entity_type="electricity_undertaking", ms_established="LU",
        )
        assessment = Assessment.objects.create(
            entity=entity, status="completed",
            description="Test", sector="energy", entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            result_model="ir_thresholds",
            result_early_warning={"recommended": False},
        )

        event = build_misp_event(assessment, entity, profile_event_uuid="prof-uuid")
        obj = event["Event"]["Object"][0]
        assert obj["ObjectReference"][0]["referenced_uuid"] == "prof-uuid"


class DictToMISPEventReferenceTest(TestCase):
    """Tests for ObjectReference handling in _dict_to_misp_event."""

    def test_object_reference_converted(self):
        from entity.misp_push import _dict_to_misp_event

        event_data = {
            "info": "Test",
            "date": "2026-04-03",
            "threat_level_id": "1",
            "analysis": "2",
            "distribution": "1",
            "Tag": [],
            "Object": [{
                "name": "cyberscale-entity-assessment",
                "uuid": "obj-uuid",
                "Attribute": [],
                "ObjectReference": [{
                    "referenced_uuid": "profile-uuid",
                    "relationship_type": "belongs-to",
                    "comment": "Entity profile",
                }],
            }],
        }

        misp_event = _dict_to_misp_event(event_data)
        assert len(misp_event.Object) == 1
        obj = misp_event.Object[0]
        assert len(obj.ObjectReference) == 1
        assert obj.ObjectReference[0].referenced_uuid == "profile-uuid"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_push.py::ObjectReferenceTest -v`
Expected: FAIL — `profile_event_uuid` parameter not accepted

- [ ] **Step 3: Add profile_event_uuid parameter to misp_export builders**

In `entity/misp_export.py`, modify all three builder function signatures:

Change `def build_misp_event(assessment, entity) -> dict:` to:
```python
def build_misp_event(assessment, entity, profile_event_uuid: str = "") -> dict:
```

After the object dict (line 74-81), before closing the `"Object"` list, add inside the object dict:

```python
                }
```

becomes:

```python
                    **({"ObjectReference": [{
                        "referenced_uuid": profile_event_uuid,
                        "relationship_type": "belongs-to",
                        "comment": "Entity profile for this assessment",
                    }]} if profile_event_uuid else {}),
                }
```

Apply the same pattern to `build_misp_event_for_type` (add `profile_event_uuid: str = ""` param, add ObjectReference to the object dict).

For `build_misp_event_global`, add `profile_event_uuid: str = ""` param and add the ObjectReference to each object in the loop:

```python
        obj_dict = {
            "name": "cyberscale-entity-assessment",
            "meta-category": "misc",
            "uuid": str(uuid.uuid4()),
            "Attribute": attrs,
        }
        if profile_event_uuid:
            obj_dict["ObjectReference"] = [{
                "referenced_uuid": profile_event_uuid,
                "relationship_type": "belongs-to",
                "comment": "Entity profile for this assessment",
            }]
        objects.append(obj_dict)
```

- [ ] **Step 4: Handle ObjectReference in misp_push.py _dict_to_misp_event**

In `entity/misp_push.py`, inside the object loop (after appending attributes, before `event.Object.append(misp_obj)`), add:

```python
        for ref_data in obj_data.get("ObjectReference", []):
            from pymisp import MISPObjectReference
            ref = MISPObjectReference()
            ref.referenced_uuid = ref_data.get("referenced_uuid", "")
            ref.relationship_type = ref_data.get("relationship_type", "")
            ref.comment = ref_data.get("comment", "")
            misp_obj.ObjectReference.append(ref)
```

Also update the hardcoded object name to use the dict's name:

Change:
```python
        misp_obj = MISPObject("cyberscale-entity-assessment", standalone=True)
```
to:
```python
        misp_obj = MISPObject(obj_data.get("name", "cyberscale-entity-assessment"), standalone=True)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_push.py::ObjectReferenceTest entity/tests/test_misp_push.py::DictToMISPEventReferenceTest -v`
Expected: ALL PASS

- [ ] **Step 6: Run full test suite to verify no regressions**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add entity/misp_export.py entity/misp_push.py entity/tests/test_misp_push.py
git commit -m "feat: add object reference linking assessments to entity profile"
```

---

### Task 6: Remove User-Facing MISP Push, Add Admin Actions

**Files:**
- Modify: `entity/views.py` (remove `assessment_misp_push_view`)
- Modify: `entity/urls.py` (remove misp-push route)
- Modify: `templates/entity/assessment_result.html` (remove push button)
- Modify: `entity/admin.py` (add fieldsets + push actions)
- Modify: `entity/tests/test_misp_push.py` (remove view tests, add admin tests)

- [ ] **Step 1: Write failing tests for admin push actions**

In `entity/tests/test_misp_push.py`, remove the entire `MISPPushViewTest` class. Then add:

```python
from django.contrib.admin.sites import AdminSite
from entity.admin import EntityAdmin, AssessmentAdmin


class AdminProfilePushTest(TestCase):
    """Tests for admin 'Push profile to MISP' action."""

    def setUp(self):
        self.superuser = User.objects.create_superuser("admin", "admin@test.com", "adminpass123")
        self.entity = Entity.objects.create(
            user=User.objects.create_user("pushentity", password="testpass123"),
            organisation_name="Push Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-key",
            address="1 Rue Test",
            contact_email="info@pushcorp.lu",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.client = Client()
        self.client.login(username="admin", password="adminpass123")

    def test_push_profile_success(self):
        with patch("entity.admin.push_event") as mock_push:
            mock_push.return_value = {
                "success": True, "event_id": "10",
                "event_uuid": "profile-uuid-returned", "error": None,
            }
            resp = self.client.post("/admin/entity/entity/", {
                "action": "push_profile_to_misp",
                "_selected_action": [str(self.entity.pk)],
            })

        assert resp.status_code == 302
        self.entity.refresh_from_db()
        assert self.entity.misp_profile_event_uuid != ""
        sub = Submission.objects.filter(target="misp_profile_push", status="success").first()
        assert sub is not None

    def test_push_profile_no_misp_config(self):
        self.entity.misp_instance_url = ""
        self.entity.save()

        resp = self.client.post("/admin/entity/entity/", {
            "action": "push_profile_to_misp",
            "_selected_action": [str(self.entity.pk)],
        })
        assert resp.status_code == 302
        assert not Submission.objects.filter(target="misp_profile_push").exists()


class AdminAssessmentPushTest(TestCase):
    """Tests for admin 'Push to MISP' action."""

    def setUp(self):
        self.superuser = User.objects.create_superuser("admin2", "admin2@test.com", "adminpass123")
        self.entity = Entity.objects.create(
            user=User.objects.create_user("assesspush", password="testpass123"),
            organisation_name="Assess Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-key",
            misp_profile_event_uuid="existing-profile-uuid",
        )
        self.assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test incident", sector="energy",
            entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": False},
                "triggered_criteria": [],
            }],
        )
        self.client = Client()
        self.client.login(username="admin2", password="adminpass123")

    def test_push_assessment_success(self):
        with patch("entity.admin.push_event") as mock_push:
            mock_push.return_value = {
                "success": True, "event_id": "20",
                "event_uuid": "assess-uuid", "error": None,
            }
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "push_to_misp",
                "_selected_action": [str(self.assessment.pk)],
            })

        assert resp.status_code == 302
        sub = Submission.objects.filter(target="misp_push", status="success").first()
        assert sub is not None
        assert sub.misp_event_id == "20"

    def test_push_assessment_blocked_without_profile(self):
        self.entity.misp_profile_event_uuid = ""
        self.entity.save()

        resp = self.client.post("/admin/entity/assessment/", {
            "action": "push_to_misp",
            "_selected_action": [str(self.assessment.pk)],
        })
        assert resp.status_code == 302
        assert not Submission.objects.filter(target="misp_push").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_push.py::AdminProfilePushTest -v`
Expected: FAIL — action does not exist

- [ ] **Step 3: Remove user-facing push view, URL, and template button**

In `entity/views.py`, remove the entire `assessment_misp_push_view` function (lines 367-411).

In `entity/urls.py`, remove the line:
```python
    path("assess/<int:pk>/misp-push/", views.assessment_misp_push_view, name="assessment_misp_push"),
```

In `templates/entity/assessment_result.html`, remove lines 138-143:
```html
  {% if entity.misp_instance_url and entity.misp_api_key %}
    <form method="post" action="{% url 'assessment_misp_push' assessment.pk %}" style="display:inline;">
      {% csrf_token %}
      <button type="submit" class="contrast">Push to MISP</button>
    </form>
  {% endif %}
```

- [ ] **Step 4: Add admin push actions to admin.py**

Replace the entire `entity/admin.py` with:

```python
import csv
import uuid as uuid_mod

from django.contrib import admin, messages
from django.http import HttpResponse

from .models import Assessment, Entity, EntityType, Submission


class EntityTypeInline(admin.TabularInline):
    model = EntityType
    fields = ("sector", "entity_type", "added_at")
    readonly_fields = ("added_at",)
    extra = 1


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


def push_profile_to_misp(modeladmin, request, queryset):
    """Push selected entity profiles to MISP."""
    from .misp_profile_export import build_misp_profile_event
    from .misp_push import push_event

    for entity in queryset:
        if not entity.misp_instance_url or not entity.misp_api_key:
            messages.error(request, f"{entity.organisation_name}: MISP URL and API key required.")
            continue

        if not entity.misp_profile_event_uuid:
            entity.misp_profile_event_uuid = str(uuid_mod.uuid4())
            entity.save(update_fields=["misp_profile_event_uuid"])

        event_dict = build_misp_profile_event(entity)

        result = push_event(entity.misp_instance_url, entity.misp_api_key, event_dict)

        if result["success"]:
            # Find an assessment to link the submission to (use latest or skip)
            latest = entity.assessments.order_by("-created_at").first()
            if latest:
                Submission.objects.create(
                    assessment=latest,
                    target="misp_profile_push",
                    misp_event_id=result["event_id"] or "",
                    status="success",
                )
            messages.success(request, f"{entity.organisation_name}: Profile pushed (ID: {result['event_id']}).")
        else:
            latest = entity.assessments.order_by("-created_at").first()
            if latest:
                Submission.objects.create(
                    assessment=latest,
                    target="misp_profile_push",
                    status="failed",
                )
            messages.error(request, f"{entity.organisation_name}: Push failed — {result['error']}")


push_profile_to_misp.short_description = "Push profile to MISP"


@admin.register(EntityType)
class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ("entity", "sector", "entity_type", "added_at")
    list_filter = ("sector",)
    search_fields = ("entity__organisation_name", "entity_type")


@admin.register(Entity)
class EntityAdmin(admin.ModelAdmin):
    list_display = ("organisation_name", "ms_established", "contact_email", "responsible_person_name", "competent_authority")
    list_filter = ("ms_established",)
    search_fields = ("organisation_name", "user__username")
    readonly_fields = ("misp_profile_event_uuid",)
    inlines = [EntityTypeInline, AssessmentInline]
    actions = [push_profile_to_misp]
    fieldsets = (
        ("Organisation", {"fields": ("user", "organisation_name", "address", "ms_established", "competent_authority")}),
        ("General Contact", {"fields": ("contact_email", "contact_phone")}),
        ("Responsible Person", {"fields": ("responsible_person_name", "responsible_person_email")}),
        ("Technical Contact", {"fields": ("technical_contact_name", "technical_contact_email", "technical_contact_phone")}),
        ("Service Provision", {"fields": ("ms_services",)}),
        ("IP Ranges", {"fields": ("ip_ranges",)}),
        ("MISP Settings", {"fields": ("misp_instance_url", "misp_api_key", "misp_default_tlp", "misp_profile_event_uuid")}),
    )


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


def push_to_misp(modeladmin, request, queryset):
    """Push selected assessments to MISP (admin action)."""
    from .misp_export import build_misp_event_global, build_misp_event
    from .misp_push import push_event

    for assessment in queryset.select_related("entity"):
        entity = assessment.entity

        if assessment.status != "completed":
            messages.error(request, f"Assessment #{assessment.pk}: Only completed assessments can be pushed.")
            continue

        if not entity.misp_instance_url or not entity.misp_api_key:
            messages.error(request, f"Assessment #{assessment.pk}: Entity MISP URL and API key required.")
            continue

        if not entity.misp_profile_event_uuid:
            messages.error(request, f"Assessment #{assessment.pk}: Entity profile must be pushed to MISP before pushing assessments.")
            continue

        if not assessment.misp_event_uuid:
            assessment.misp_event_uuid = str(uuid_mod.uuid4())
            assessment.save(update_fields=["misp_event_uuid"])

        profile_uuid = entity.misp_profile_event_uuid

        if assessment.assessment_results:
            event_dict = build_misp_event_global(assessment, entity, profile_event_uuid=profile_uuid)
        else:
            event_dict = build_misp_event(assessment, entity, profile_event_uuid=profile_uuid)

        result = push_event(entity.misp_instance_url, entity.misp_api_key, event_dict)

        if result["success"]:
            Submission.objects.create(
                assessment=assessment,
                target="misp_push",
                misp_event_id=result["event_id"] or "",
                status="success",
            )
            messages.success(request, f"Assessment #{assessment.pk}: Pushed (ID: {result['event_id']}).")
        else:
            Submission.objects.create(
                assessment=assessment,
                target="misp_push",
                status="failed",
            )
            messages.error(request, f"Assessment #{assessment.pk}: Push failed — {result['error']}")


push_to_misp.short_description = "Push to MISP"


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
        "result_early_warning", "result_raw", "misp_event_uuid",
    )
    actions = [export_assessments_csv, push_to_misp]


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

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_push.py -v`
Expected: ALL PASS (view tests removed, admin tests pass, module tests still pass)

- [ ] **Step 6: Run full web test suite**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add entity/views.py entity/urls.py entity/admin.py templates/entity/assessment_result.html entity/tests/test_misp_push.py
git commit -m "feat: move MISP push to admin-only actions with profile + assessment push"
```

---

### Task 7: MS Affected Filtering in Assessment Form

**Files:**
- Modify: `entity/views.py` (`impact_fields_view`)
- Modify: `templates/entity/partials/impact_fields.html`
- Test: `entity/tests/test_profile.py`

- [ ] **Step 1: Write failing tests for MS filtering**

Append to `entity/tests/test_profile.py`:

```python
class MSAffectedFilteringTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("msfilter", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Filter Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            ms_services=["LU", "BE", "DE"],
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.client = Client()
        self.client.login(username="msfilter", password="testpass123")

    def test_ms_filtered_when_services_set(self):
        resp = self.client.get("/htmx/impact-fields/?types=energy:electricity_undertaking")
        assert resp.status_code == 200
        content = resp.content.decode()
        # Should have LU, BE, DE (from ms_services + ms_established)
        assert 'value="LU"' in content
        assert 'value="BE"' in content
        assert 'value="DE"' in content
        # Should NOT have FR, IT, etc.
        assert 'value="FR"' not in content
        assert 'value="IT"' not in content

    def test_ms_all_when_services_empty(self):
        self.entity.ms_services = []
        self.entity.save()
        resp = self.client.get("/htmx/impact-fields/?types=energy:electricity_undertaking")
        content = resp.content.decode()
        # All 27 MS should be present
        assert 'value="FR"' in content
        assert 'value="IT"' in content
        assert 'value="LU"' in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py::MSAffectedFilteringTest -v`
Expected: FAIL — FR/IT still present when ms_services is set

- [ ] **Step 3: Update impact_fields_view to pass allowed_ms**

In `entity/views.py`, modify `impact_fields_view` (currently at line ~461). The view currently doesn't have access to the entity. Change it to:

```python
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
```

Add `from .models import Entity` if not already imported at the top (it's already imported via the models import on line 21).

- [ ] **Step 4: Update impact_fields.html to use allowed_ms**

Replace the MS `<select>` block in `templates/entity/partials/impact_fields.html` (lines 6-23) with:

```html
  <label>Member states affected
    <select name="impact_{{ forloop.counter0 }}_ms_affected" multiple size="4">
      {% if allowed_ms %}
        {% for ms in allowed_ms %}
          <option value="{{ ms }}" {% if ms == "LU" %}selected{% endif %}>{{ ms }}</option>
        {% endfor %}
      {% else %}
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
      {% endif %}
    </select>
  </label>
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_profile.py::MSAffectedFilteringTest -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add entity/views.py templates/entity/partials/impact_fields.html entity/tests/test_profile.py
git commit -m "feat: filter MS affected checkboxes based on entity ms_services"
```

---

### Task 8: Docker Compose — MISP Instance

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add MISP containers to docker-compose.yml**

Add after the `cyberscale-web` service and before the `volumes:` section:

```yaml
  misp-db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: misp_dev
      MYSQL_ROOT_PASSWORD: misp_root_dev
    volumes:
      - misp_db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-pmisp_root_dev"]
      interval: 10s
      timeout: 5s
      retries: 10

  misp-redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  misp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    environment:
      MYSQL_HOST: misp-db
      MYSQL_PORT: "3306"
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: misp_dev
      REDIS_HOST: misp-redis
      BASE_URL: "https://localhost"
      ADMIN_EMAIL: "admin@admin.test"
      ADMIN_PASSWORD: "admin"
      ADMIN_KEY: "cyberscale-misp-test-api-key"
      NOREDIR: "true"
    ports:
      - "8443:443"
    depends_on:
      misp-db:
        condition: service_healthy
      misp-redis:
        condition: service_healthy
```

Add to the `cyberscale-web` service `environment` section:

```yaml
      MISP_URL: "https://misp"
      MISP_API_KEY: "cyberscale-misp-test-api-key"
```

Add to the `volumes:` section:

```yaml
  misp_db_data:
```

- [ ] **Step 2: Build and start**

Run: `docker compose build`
Run: `docker compose up -d`
Run: `docker compose ps` — verify all containers are running

- [ ] **Step 3: Verify MISP is reachable**

Run: `docker compose exec cyberscale-web python -c "from pymisp import PyMISP; m = PyMISP('https://misp', 'cyberscale-misp-test-api-key', ssl=False); print(m.get_version())"`

Expected: MISP version dict (may take 1-2 minutes for MISP to initialize on first run)

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "infra: add MISP instance to Docker Compose for integration testing"
```

---

### Task 9: MISP Integration Tests (Real Instance)

**Files:**
- Create: `entity/tests/test_misp_integration.py`

- [ ] **Step 1: Create integration test file**

Create `entity/tests/test_misp_integration.py`:

```python
"""Integration tests against a real MISP instance in Docker.

These tests require the MISP container to be running.
Run with: docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_integration.py -v
Skip if MISP is not available.
"""

import os
import uuid

import pytest
from django.contrib.auth.models import User
from django.test import TestCase

from entity.models import Assessment, Entity, EntityType


MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")

requires_misp = pytest.mark.skipif(
    not MISP_URL or not MISP_API_KEY,
    reason="MISP_URL and MISP_API_KEY not set",
)


@requires_misp
class MISPProfilePushIntegrationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("integ", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name=f"IntegTest-{uuid.uuid4().hex[:8]}",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url=MISP_URL,
            misp_api_key=MISP_API_KEY,
            address="42 Rue Integration",
            contact_email="integ@test.lu",
            responsible_person_name="Alice Test",
            responsible_person_email="alice@test.lu",
            technical_contact_name="Bob Test",
            technical_contact_email="bob@test.lu",
            ip_ranges=["10.0.0.0/8"],
            ms_services=["LU", "BE"],
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )

    def test_push_profile_creates_event(self):
        from entity.misp_profile_export import build_misp_profile_event
        from entity.misp_push import push_event

        self.entity.misp_profile_event_uuid = str(uuid.uuid4())
        self.entity.save(update_fields=["misp_profile_event_uuid"])

        event_dict = build_misp_profile_event(self.entity)
        result = push_event(MISP_URL, MISP_API_KEY, event_dict)

        assert result["success"] is True, f"Push failed: {result['error']}"
        assert result["event_id"]

    def test_push_assessment_with_reference(self):
        from entity.misp_profile_export import build_misp_profile_event
        from entity.misp_export import build_misp_event_global
        from entity.misp_push import push_event

        # Push profile first
        self.entity.misp_profile_event_uuid = str(uuid.uuid4())
        self.entity.save(update_fields=["misp_profile_event_uuid"])

        profile_dict = build_misp_profile_event(self.entity)
        profile_result = push_event(MISP_URL, MISP_API_KEY, profile_dict)
        assert profile_result["success"] is True

        # Push assessment with reference
        assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Integration test incident",
            sector="energy", entity_type="electricity_undertaking",
            misp_event_uuid=str(uuid.uuid4()),
            result_significance_label="SIGNIFICANT",
            result_model="ir_thresholds",
            result_early_warning={"recommended": True, "deadline": "24h"},
            assessment_results=[{
                "sector": "energy",
                "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT",
                "model": "ir_thresholds",
                "early_warning": {"recommended": True, "deadline": "24h"},
                "triggered_criteria": ["service_impact >= degraded"],
                "service_impact": "unavailable",
                "data_impact": "compromised",
                "safety_impact": "none",
                "financial_impact": "significant",
                "affected_persons_count": 50000,
                "impact_duration_hours": 4,
            }],
        )

        event_dict = build_misp_event_global(
            assessment, self.entity,
            profile_event_uuid=self.entity.misp_profile_event_uuid,
        )
        result = push_event(MISP_URL, MISP_API_KEY, event_dict)

        assert result["success"] is True, f"Push failed: {result['error']}"
        assert result["event_id"]

    def test_push_with_bad_credentials_fails(self):
        from entity.misp_push import push_event

        result = push_event(MISP_URL, "invalid-key", {"Event": {"info": "Bad", "Tag": [], "Object": []}})
        assert result["success"] is False
```

- [ ] **Step 2: Run integration tests**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_misp_integration.py -v`
Expected: ALL PASS (or SKIP if MISP not running)

- [ ] **Step 3: Commit**

```bash
git add entity/tests/test_misp_integration.py
git commit -m "test: add real MISP integration tests for profile and assessment push"
```

---

### Task 10: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full web test suite**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v`
Expected: ALL PASS

- [ ] **Step 2: Run core library tests**

Run: `docker compose exec cyberscale-web python -m pytest src/tests/ -v --ignore=src/tests/test_cwe_enrichment.py --ignore=src/tests/test_generation_balance.py --ignore=src/tests/test_mix_curated.py --ignore=src/tests/test_weighted_loss.py`
Expected: ALL PASS

- [ ] **Step 3: Manual smoke test**

1. Open `http://localhost:8000/`
2. Log in, click "Edit Profile", fill in Art. 27 fields with test IP ranges
3. Save — verify fields persist
4. Create an assessment — verify MS affected is filtered to ms_services
5. Open Django admin, select entity → "Push profile to MISP" → verify success message
6. Select assessment → "Push to MISP" → verify success with profile reference
7. Open MISP at `https://localhost:8443`, log in (admin@admin.test / admin), verify both events exist and assessment references profile

- [ ] **Step 4: Commit any fixes from smoke testing**

```bash
git add -A
git commit -m "fix: smoke test adjustments for Art. 27 entity profile"
```
