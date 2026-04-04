# Art. 23 Early Warning (v1.3) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entity submits Art. 23(4)(a) early warning through cyberscale-web, pushed to MISP-A as an object on the assessment event, with lifecycle managed by admin via MISP tags. Entity sees status on result page.

**Architecture:** Early warning form pre-fills from assessment. On submit, a `cyberscale-early-warning` MISP object is added to the existing assessment event via PyMISP `direct_call`. Lifecycle state lives as MISP tags (source of truth). Admin actions update tags. Entity result page queries MISP for current status.

**Tech Stack:** Django 5.x, PyMISP >=2.4, MISP Docker, Pico CSS

---

## File Structure

| File | Responsibility |
|---|---|
| `entity/models.py` | Add `early_warning` to Submission TARGET_CHOICES |
| `entity/forms.py` | New `EarlyWarningForm` |
| `entity/views.py` | Add `early_warning_view`, update `assessment_result_view` for status |
| `entity/urls.py` | Add `/assess/<pk>/early-warning/` |
| `entity/misp_push.py` | Add `add_object_to_event()` and `update_event_tags()` helpers |
| `entity/admin.py` | Add lifecycle admin actions |
| `data/misp-objects/cyberscale-early-warning/definition.json` | New object template |
| `scripts/misp-init.sh` | Register new template |
| `templates/entity/early_warning_form.html` | New form template |
| `templates/entity/assessment_result.html` | Add submit button + status card |
| `entity/tests/test_early_warning.py` | New test suite |

---

### Task 1: Submission Target + MISP Object Template

**Files:**
- Modify: `entity/models.py`
- Create: `data/misp-objects/cyberscale-early-warning/definition.json`
- Modify: `scripts/misp-init.sh` (no code test needed)

- [ ] **Step 1: Add early_warning to Submission TARGET_CHOICES**

In `entity/models.py`, in `Submission.TARGET_CHOICES`, add after `("misp_profile_push", "MISP Profile Push")`:

```python
        ("early_warning", "Early Warning"),
```

- [ ] **Step 2: Create MISP object template**

Create `data/misp-objects/cyberscale-early-warning/definition.json`:

```json
{
  "name": "cyberscale-early-warning",
  "meta-category": "misc",
  "description": "CyberScale NIS2 Art. 23(4)(a) early warning notification",
  "version": 1,
  "uuid": "c5e0f001-e27a-4f00-a000-000000000003",
  "attributes": {
    "submission-timestamp": {"misp-attribute": "datetime", "ui-priority": 1, "description": "When the early warning was submitted"},
    "deadline": {"misp-attribute": "text", "ui-priority": 2, "description": "Notification deadline (24h NIS2, 4h DORA)"},
    "suspected-malicious": {"misp-attribute": "boolean", "ui-priority": 3, "description": "Entity-confirmed: suspected malicious"},
    "cross-border-impact": {"misp-attribute": "boolean", "ui-priority": 4, "description": "Entity-confirmed: cross-border impact"},
    "initial-assessment": {"misp-attribute": "text", "ui-priority": 5, "description": "Entity free-text initial assessment"},
    "support-requested": {"misp-attribute": "boolean", "ui-priority": 6, "description": "Entity requests CSIRT assistance"},
    "support-description": {"misp-attribute": "text", "ui-priority": 7, "description": "Nature of support needed"},
    "notification-recipient": {"misp-attribute": "text", "ui-priority": 8, "description": "CA or CSIRT abbreviation"}
  }
}
```

- [ ] **Step 3: Register template in MISP**

Run: `docker compose exec misp /scripts/misp-init.sh`

The script already handles all `cyberscale-*` directories in `/misp-objects/`.

- [ ] **Step 4: Commit**

```bash
git add entity/models.py data/misp-objects/cyberscale-early-warning/
git commit -m "feat: add early_warning submission target and MISP object template"
```

---

### Task 2: MISP Push Helpers — add_object_to_event + update_event_tags

**Files:**
- Modify: `entity/misp_push.py`
- Create: `entity/tests/test_early_warning.py`

- [ ] **Step 1: Write failing tests**

Create `entity/tests/test_early_warning.py`:

```python
"""Tests for Art. 23 early warning submission and lifecycle."""

from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase
from django.utils import timezone

from entity.models import Assessment, Entity, EntityType, Submission


class MISPPushHelpersTest(TestCase):
    """Tests for add_object_to_event and update_event_tags."""

    def test_add_object_to_event_success(self):
        from entity.misp_push import add_object_to_event

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.direct_call.return_value = {
                "Object": {"id": "42", "uuid": "obj-uuid-123"}
            }

            result = add_object_to_event(
                "https://misp.example.org", "key", "5",
                {"name": "cyberscale-early-warning", "Attribute": []},
            )

        assert result["success"] is True
        assert result["object_id"] == "42"

    def test_add_object_to_event_failure(self):
        from entity.misp_push import add_object_to_event

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.direct_call.return_value = {
                "errors": "Could not add object"
            }

            result = add_object_to_event(
                "https://misp.example.org", "key", "5",
                {"name": "test", "Attribute": []},
            )

        assert result["success"] is False
        assert "Could not add object" in result["error"]

    def test_update_event_tags_success(self):
        from entity.misp_push import update_event_tags

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.direct_call.side_effect = [
                {"Event": {"Tag": [{"id": "99", "name": 'cyberscale:notification-status="received"'}]}},
                {"saved": True},
                {"saved": True},
            ]

            result = update_event_tags(
                "https://misp.example.org", "key", "5",
                remove_prefix="cyberscale:notification-status",
                add_tag='cyberscale:notification-status="acknowledged"',
            )

        assert result["success"] is True

    def test_get_event_tags_success(self):
        from entity.misp_push import get_event_tags

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.direct_call.return_value = {
                "Event": {"Tag": [
                    {"name": 'cyberscale:notification-status="received"'},
                    {"name": "tlp:amber"},
                ]}
            }

            tags = get_event_tags("https://misp.example.org", "key", "5")

        assert 'cyberscale:notification-status="received"' in tags
        assert "tlp:amber" in tags
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::MISPPushHelpersTest -v`
Expected: FAIL — functions don't exist

- [ ] **Step 3: Implement helpers in misp_push.py**

Add to `entity/misp_push.py` after the `push_event` function:

```python
def add_object_to_event(
    misp_url: str, misp_api_key: str, event_id: str,
    object_dict: dict, ssl: bool = True,
) -> dict:
    """Add a MISP object to an existing event.

    Returns dict with: success, object_id, error
    """
    try:
        misp = PyMISP(misp_url, misp_api_key, ssl=ssl, timeout=30)
    except Exception as exc:
        logger.error("Failed to connect to MISP: %s", exc)
        return {"success": False, "object_id": None, "error": str(exc)}

    try:
        response = misp.direct_call(f"objects/add/{event_id}", {"Object": object_dict})

        if isinstance(response, dict) and "errors" in response:
            error_msg = str(response["errors"])
            logger.error("MISP add_object rejected: %s", error_msg)
            return {"success": False, "object_id": None, "error": error_msg}

        if isinstance(response, dict) and "Object" in response:
            obj_id = str(response["Object"].get("id", ""))
            logger.info("MISP object added: id=%s to event=%s", obj_id, event_id)
            return {"success": True, "object_id": obj_id, "error": None}

        return {"success": True, "object_id": "", "error": None}

    except Exception as exc:
        logger.error("MISP add_object failed: %s", exc)
        return {"success": False, "object_id": None, "error": str(exc)}


def update_event_tags(
    misp_url: str, misp_api_key: str, event_id: str,
    remove_prefix: str = "", add_tag: str = "", ssl: bool = True,
) -> dict:
    """Update tags on a MISP event. Removes tags matching prefix, adds new tag.

    Returns dict with: success, error
    """
    try:
        misp = PyMISP(misp_url, misp_api_key, ssl=ssl, timeout=30)
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    try:
        event = misp.direct_call(f"events/view/{event_id}")
        if not isinstance(event, dict) or "Event" not in event:
            return {"success": False, "error": "Event not found"}

        existing_tags = event["Event"].get("Tag", [])

        if remove_prefix:
            for tag in existing_tags:
                if tag["name"].startswith(remove_prefix):
                    misp.direct_call(f"tags/removeTagFromEvent/{event_id}/{tag['id']}")

        if add_tag:
            misp.direct_call("events/addTag", {"event": event_id, "tag": add_tag})

        return {"success": True, "error": None}

    except Exception as exc:
        logger.error("MISP tag update failed: %s", exc)
        return {"success": False, "error": str(exc)}


def get_event_tags(
    misp_url: str, misp_api_key: str, event_id: str, ssl: bool = True,
) -> list[str]:
    """Get all tag names for a MISP event. Returns empty list on failure."""
    try:
        misp = PyMISP(misp_url, misp_api_key, ssl=ssl, timeout=30)
        event = misp.direct_call(f"events/view/{event_id}")
        if isinstance(event, dict) and "Event" in event:
            return [t["name"] for t in event["Event"].get("Tag", [])]
    except Exception:
        pass
    return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::MISPPushHelpersTest -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/misp_push.py entity/tests/test_early_warning.py
git commit -m "feat: add MISP helpers for object addition and tag management"
```

---

### Task 3: Early Warning Form

**Files:**
- Modify: `entity/forms.py`
- Test: `entity/tests/test_early_warning.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_early_warning.py`:

```python
class EarlyWarningFormTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ewform", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="EW Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )

    def test_form_fields_exist(self):
        from entity.forms import EarlyWarningForm
        form = EarlyWarningForm()
        assert "suspected_malicious" in form.fields
        assert "cross_border_impact" in form.fields
        assert "initial_assessment" in form.fields
        assert "support_requested" in form.fields
        assert "support_description" in form.fields

    def test_form_requires_initial_assessment(self):
        from entity.forms import EarlyWarningForm
        form = EarlyWarningForm(data={
            "suspected_malicious": True,
            "cross_border_impact": False,
            "initial_assessment": "",
        })
        assert not form.is_valid()
        assert "initial_assessment" in form.errors

    def test_form_valid_without_support(self):
        from entity.forms import EarlyWarningForm
        form = EarlyWarningForm(data={
            "suspected_malicious": True,
            "cross_border_impact": False,
            "initial_assessment": "SCADA compromise detected.",
            "support_requested": False,
        })
        assert form.is_valid(), form.errors

    def test_form_requires_support_description_when_requested(self):
        from entity.forms import EarlyWarningForm
        form = EarlyWarningForm(data={
            "suspected_malicious": True,
            "cross_border_impact": False,
            "initial_assessment": "Incident detected.",
            "support_requested": True,
            "support_description": "",
        })
        assert not form.is_valid()
        assert "support_description" in form.errors

    def test_form_valid_with_support(self):
        from entity.forms import EarlyWarningForm
        form = EarlyWarningForm(data={
            "suspected_malicious": True,
            "cross_border_impact": True,
            "initial_assessment": "Incident detected.",
            "support_requested": True,
            "support_description": "Need forensic analysis support.",
        })
        assert form.is_valid(), form.errors
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::EarlyWarningFormTest -v`
Expected: FAIL — `EarlyWarningForm` does not exist

- [ ] **Step 3: Implement EarlyWarningForm**

Add to `entity/forms.py`:

```python
class EarlyWarningForm(forms.Form):
    """Art. 23(4)(a) early warning submission form."""

    suspected_malicious = forms.BooleanField(required=False, label="Suspected malicious activity")
    cross_border_impact = forms.BooleanField(required=False, label="Cross-border impact")
    initial_assessment = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6, "placeholder": "Describe the incident: what happened, what systems are affected, current status..."}),
        label="Initial assessment",
    )
    support_requested = forms.BooleanField(required=False, label="Request CSIRT support")
    support_description = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Describe the support needed (e.g., forensic analysis, containment assistance)..."}),
        required=False,
        label="Support description",
    )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("support_requested") and not cleaned.get("support_description", "").strip():
            self.add_error("support_description", "Please describe the support needed.")
        return cleaned
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::EarlyWarningFormTest -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/forms.py entity/tests/test_early_warning.py
git commit -m "feat: add EarlyWarningForm with support request validation"
```

---

### Task 4: Early Warning View + URL + Template

**Files:**
- Modify: `entity/views.py`
- Modify: `entity/urls.py`
- Create: `templates/entity/early_warning_form.html`
- Test: `entity/tests/test_early_warning.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_early_warning.py`:

```python
class EarlyWarningViewTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("ewview", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="EW View Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-key",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test incident", sector="energy",
            entity_type="electricity_undertaking",
            result_significance=True,
            result_significance_label="SIGNIFICANT",
            result_framework="NIS2 (ILR)",
            result_competent_authority="ILR",
            result_early_warning={"recommended": True, "deadline": "24h"},
            misp_event_uuid="test-event-uuid",
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": True, "deadline": "24h"},
                "triggered_criteria": ["service_impact >= degraded"],
                "competent_authority": "ILR", "csirt": "CIRCL",
                "notification_recipient": "ILR",
            }],
        )
        self.client = Client()
        self.client.login(username="ewview", password="testpass123")

    def test_form_loads(self):
        resp = self.client.get(f"/assess/{self.assessment.pk}/early-warning/")
        assert resp.status_code == 200
        assert b"Early Warning" in resp.content
        assert b"Initial assessment" in resp.content

    def test_form_requires_login(self):
        c = Client()
        resp = c.get(f"/assess/{self.assessment.pk}/early-warning/")
        assert resp.status_code == 302
        assert "/login/" in resp.url

    def test_form_404_for_draft(self):
        draft = Assessment.objects.create(
            entity=self.entity, status="draft",
            description="Draft", sector="energy",
            entity_type="electricity_undertaking",
        )
        resp = self.client.get(f"/assess/{draft.pk}/early-warning/")
        assert resp.status_code == 404

    def test_form_404_when_not_recommended(self):
        no_ew = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="No EW", sector="energy",
            entity_type="electricity_undertaking",
            result_early_warning={"recommended": False},
        )
        resp = self.client.get(f"/assess/{no_ew.pk}/early-warning/")
        assert resp.status_code == 404

    def test_submit_creates_submission(self):
        with patch("entity.views.add_object_to_event") as mock_add, \
             patch("entity.views.update_event_tags") as mock_tags:
            mock_add.return_value = {"success": True, "object_id": "10", "error": None}
            mock_tags.return_value = {"success": True, "error": None}

            resp = self.client.post(f"/assess/{self.assessment.pk}/early-warning/", {
                "suspected_malicious": "on",
                "initial_assessment": "SCADA compromise detected at substation.",
            })

        assert resp.status_code == 302
        sub = Submission.objects.filter(target="early_warning", assessment=self.assessment).first()
        assert sub is not None
        assert sub.status == "success"

    def test_submit_blocked_when_already_submitted(self):
        Submission.objects.create(
            assessment=self.assessment, target="early_warning", status="success",
        )
        resp = self.client.get(f"/assess/{self.assessment.pk}/early-warning/")
        assert resp.status_code == 302  # redirects back to result

    def test_result_page_shows_submit_button(self):
        resp = self.client.get(f"/assess/{self.assessment.pk}/")
        assert b"Submit Early Warning" in resp.content

    def test_result_page_hides_button_when_submitted(self):
        Submission.objects.create(
            assessment=self.assessment, target="early_warning", status="success",
        )
        resp = self.client.get(f"/assess/{self.assessment.pk}/")
        assert b"Submit Early Warning" not in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::EarlyWarningViewTest -v`
Expected: FAIL — view does not exist

- [ ] **Step 3: Add early_warning_view to views.py**

Add to `entity/views.py` after `assessment_result_view`:

```python
@login_required
def early_warning_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")

    assessment = get_object_or_404(Assessment, pk=pk, entity=entity, status="completed")

    # Must have early warning recommended
    if not assessment.result_early_warning.get("recommended"):
        from django.http import Http404
        raise Http404

    # Must not already be submitted
    if assessment.submissions.filter(target="early_warning").exists():
        messages.info(request, "Early warning already submitted.")
        return redirect("assessment_result", pk=pk)

    from .forms import EarlyWarningForm

    if request.method == "POST":
        form = EarlyWarningForm(request.POST)
        if form.is_valid():
            from .misp_push import add_object_to_event, update_event_tags
            import os

            deadline = "4h" if "DORA" in (assessment.result_framework or "") else "24h"
            now = timezone.now()

            # Build early warning object
            ew_object = {
                "name": "cyberscale-early-warning",
                "meta-category": "misc",
                "template_uuid": "c5e0f001-e27a-4f00-a000-000000000003",
                "template_version": "1",
                "Attribute": [
                    {"object_relation": "submission-timestamp", "type": "datetime", "value": now.strftime("%Y-%m-%dT%H:%M:%S+0000")},
                    {"object_relation": "deadline", "type": "text", "value": deadline},
                    {"object_relation": "suspected-malicious", "type": "boolean", "value": "1" if form.cleaned_data["suspected_malicious"] else "0"},
                    {"object_relation": "cross-border-impact", "type": "boolean", "value": "1" if form.cleaned_data["cross_border_impact"] else "0"},
                    {"object_relation": "initial-assessment", "type": "text", "value": form.cleaned_data["initial_assessment"]},
                    {"object_relation": "support-requested", "type": "boolean", "value": "1" if form.cleaned_data["support_requested"] else "0"},
                    {"object_relation": "notification-recipient", "type": "text", "value": assessment.result_competent_authority},
                ],
            }
            if form.cleaned_data.get("support_description"):
                ew_object["Attribute"].append(
                    {"object_relation": "support-description", "type": "text", "value": form.cleaned_data["support_description"]},
                )

            misp_url = entity.misp_instance_url
            misp_key = entity.misp_api_key
            ssl = os.environ.get("MISP_SSL_VERIFY", "").lower() not in ("0", "false", "no", "")

            # Get MISP event ID from Submission records
            push_sub = assessment.submissions.filter(target="misp_push", status="success").first()
            event_id = push_sub.misp_event_id if push_sub else ""

            if not event_id or not misp_url or not misp_key:
                messages.error(request, "Assessment must be pushed to MISP before submitting early warning.")
                return redirect("assessment_result", pk=pk)

            result = add_object_to_event(misp_url, misp_key, event_id, ew_object, ssl=ssl)

            if result["success"]:
                # Add lifecycle tags
                tags_to_add = [
                    'nis2:notification-stage="early-warning"',
                    'cyberscale:notification-status="received"',
                ]
                if form.cleaned_data["support_requested"]:
                    tags_to_add.append('cyberscale:support-requested="true"')

                for tag in tags_to_add:
                    update_event_tags(misp_url, misp_key, event_id, add_tag=tag, ssl=ssl)

                Submission.objects.create(
                    assessment=assessment, target="early_warning", status="success",
                )
                messages.success(request, f"Early warning submitted. Deadline: {deadline} from now.")
            else:
                Submission.objects.create(
                    assessment=assessment, target="early_warning", status="failed",
                )
                messages.error(request, f"Early warning submission failed: {result['error']}")

            return redirect("assessment_result", pk=pk)
    else:
        # Pre-fill from assessment
        form = EarlyWarningForm(initial={
            "suspected_malicious": assessment.suspected_malicious,
            "cross_border_impact": bool(
                assessment.ms_affected and
                any(ms != entity.ms_established for ms in assessment.ms_affected)
            ),
        })

    # Gather display context
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
```

Also update `assessment_result_view` to pass early warning submission status:

In `assessment_result_view`, change the render call to include:

```python
    ew_submitted = assessment.submissions.filter(target="early_warning", status="success").exists()
    ew_recommended = assessment.result_early_warning.get("recommended", False)

    return render(request, "entity/assessment_result.html", {
        "entity": entity,
        "assessment": assessment,
        "ew_submitted": ew_submitted,
        "ew_recommended": ew_recommended,
    })
```

- [ ] **Step 4: Add URL**

In `entity/urls.py`, add after the misp-json path:

```python
    path("assess/<int:pk>/early-warning/", views.early_warning_view, name="early_warning"),
```

- [ ] **Step 5: Create early_warning_form.html**

Create `templates/entity/early_warning_form.html`:

```html
{% extends "base.html" %}
{% block title %}Early Warning — Assessment #{{ assessment.pk }} — CyberScale{% endblock %}

{% block content %}
<div class="cs-page-header">
  <h2>Submit Early Warning</h2>
  <p>Assessment #{{ assessment.pk }} — {{ entity.organisation_name }}</p>
</div>

<div class="cs-card">
  <h3>Assessment Summary</h3>
  <p><strong>Significance:</strong> <span class="badge badge-significant">{{ assessment.result_significance_label }}</span></p>
  <p><strong>Framework:</strong> {{ assessment.result_framework }}</p>
  <p><strong>Notify:</strong> {{ notification_recipient }}{% if csirt %} (CSIRT: {{ csirt }}){% endif %}</p>
  <p><strong>Deadline:</strong> {{ deadline }} from submission</p>
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
    <legend>Art. 23(4)(a) Early Warning</legend>

    <label>
      {{ form.suspected_malicious }} Incident is suspected to be caused by unlawful or malicious acts
    </label>

    <label>
      {{ form.cross_border_impact }} Incident has or could have cross-border impact
    </label>

    <label>Initial assessment (required)
      {{ form.initial_assessment }}
    </label>
  </fieldset>

  <fieldset>
    <legend>CSIRT Support</legend>

    <label>
      {{ form.support_requested }} Request assistance from CSIRT
    </label>

    <label>Support description (required if requesting support)
      {{ form.support_description }}
    </label>
  </fieldset>

  <div class="cs-actions">
    <button type="submit" class="contrast">Submit Early Warning</button>
    <a href="{% url 'assessment_result' assessment.pk %}" role="button" class="outline">Cancel</a>
  </div>
</form>

<br>
<small style="color: var(--cs-text-muted);">
  By submitting, this early warning will be sent to {{ notification_recipient }} per NIS2 Art. 23(4)(a).
  You must follow up with an incident notification within 72 hours per Art. 23(4)(b).
</small>
{% endblock %}
```

- [ ] **Step 6: Update assessment_result.html**

In `templates/entity/assessment_result.html`, before the `{# Actions #}` comment (line 131), add:

```html
{# Early warning status / submit button #}
{% if ew_submitted %}
<div class="cs-card">
  <h3>Early Warning Status</h3>
  <p><span class="badge badge-model">SUBMITTED</span></p>
  <p>Check status updates in the assessment details.</p>
</div>
{% elif ew_recommended %}
<div class="cs-card" style="border-left: 3px solid var(--cs-significant);">
  <h3>Early Warning Recommended</h3>
  <p>Deadline: {{ assessment.result_early_warning.deadline }} from awareness</p>
  <a href="{% url 'early_warning' assessment.pk %}" role="button" class="contrast">Submit Early Warning</a>
</div>
{% endif %}
```

- [ ] **Step 7: Run tests**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py -v`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add entity/views.py entity/urls.py entity/forms.py templates/entity/early_warning_form.html templates/entity/assessment_result.html entity/tests/test_early_warning.py
git commit -m "feat: Art. 23 early warning submission form with MISP push"
```

---

### Task 5: Admin Lifecycle Actions

**Files:**
- Modify: `entity/admin.py`
- Test: `entity/tests/test_early_warning.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_early_warning.py`:

```python
class AdminLifecycleTest(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser("ewadmin", "admin@test.com", "adminpass123")
        self.entity = Entity.objects.create(
            user=User.objects.create_user("ewentity", password="testpass123"),
            organisation_name="EW Admin Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-key",
        )
        self.assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test", sector="energy",
            entity_type="electricity_undertaking",
            misp_event_uuid="lifecycle-event-uuid",
            result_early_warning={"recommended": True, "deadline": "24h"},
        )
        # Simulate submitted early warning
        Submission.objects.create(
            assessment=self.assessment, target="early_warning", status="success",
        )
        Submission.objects.create(
            assessment=self.assessment, target="misp_push", status="success",
            misp_event_id="42",
        )
        self.client = Client()
        self.client.login(username="ewadmin", password="adminpass123")

    def test_acknowledge_action(self):
        with patch("entity.admin.update_event_tags") as mock_tags:
            mock_tags.return_value = {"success": True, "error": None}
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "acknowledge_early_warning",
                "_selected_action": [str(self.assessment.pk)],
            })
        assert resp.status_code == 302
        mock_tags.assert_called()

    def test_close_action(self):
        with patch("entity.admin.update_event_tags") as mock_tags:
            mock_tags.return_value = {"success": True, "error": None}
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "close_early_warning",
                "_selected_action": [str(self.assessment.pk)],
            })
        assert resp.status_code == 302
        mock_tags.assert_called()

    def test_action_skips_without_early_warning(self):
        no_ew = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="No EW", sector="energy",
            entity_type="electricity_undertaking",
        )
        with patch("entity.admin.update_event_tags") as mock_tags:
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "acknowledge_early_warning",
                "_selected_action": [str(no_ew.pk)],
            })
        assert resp.status_code == 302
        mock_tags.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::AdminLifecycleTest -v`
Expected: FAIL — actions don't exist

- [ ] **Step 3: Add lifecycle actions to admin.py**

Add these functions before `AssessmentAdmin` in `entity/admin.py`:

```python
def _update_ew_status(request, queryset, new_status):
    """Shared logic for early warning lifecycle actions."""
    from .misp_push import update_event_tags

    for assessment in queryset.select_related("entity"):
        entity = assessment.entity
        if not assessment.submissions.filter(target="early_warning", status="success").exists():
            messages.warning(request, f"Assessment #{assessment.pk}: No early warning submitted.")
            continue

        push_sub = assessment.submissions.filter(target="misp_push", status="success").first()
        if not push_sub or not push_sub.misp_event_id:
            messages.error(request, f"Assessment #{assessment.pk}: No MISP event ID.")
            continue

        result = update_event_tags(
            entity.misp_instance_url, entity.misp_api_key,
            push_sub.misp_event_id,
            remove_prefix="cyberscale:notification-status",
            add_tag=f'cyberscale:notification-status="{new_status}"',
            ssl=MISP_SSL_VERIFY,
        )

        if result["success"]:
            messages.success(request, f"Assessment #{assessment.pk}: Status → {new_status}")
        else:
            messages.error(request, f"Assessment #{assessment.pk}: Failed — {result['error']}")


def acknowledge_early_warning(modeladmin, request, queryset):
    _update_ew_status(request, queryset, "acknowledged")

acknowledge_early_warning.short_description = "Acknowledge early warning"


def mark_under_review(modeladmin, request, queryset):
    _update_ew_status(request, queryset, "under-review")

mark_under_review.short_description = "Mark early warning under review"


def dispatch_support(modeladmin, request, queryset):
    _update_ew_status(request, queryset, "support-dispatched")

dispatch_support.short_description = "Dispatch CSIRT support"


def close_early_warning(modeladmin, request, queryset):
    _update_ew_status(request, queryset, "closed")

close_early_warning.short_description = "Close early warning"
```

Add the actions to `AssessmentAdmin.actions`:

```python
    actions = [export_assessments_csv, push_to_misp, acknowledge_early_warning, mark_under_review, dispatch_support, close_early_warning]
```

- [ ] **Step 4: Run tests**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/admin.py entity/tests/test_early_warning.py
git commit -m "feat: admin lifecycle actions for early warning (acknowledge, review, dispatch, close)"
```

---

### Task 6: Entity Status Card — MISP Tag Query

**Files:**
- Modify: `entity/views.py` (assessment_result_view)
- Modify: `templates/entity/assessment_result.html`
- Test: `entity/tests/test_early_warning.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_early_warning.py`:

```python
class EarlyWarningStatusTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("ewstatus", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="EW Status Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-key",
        )
        self.assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test", sector="energy",
            entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            result_early_warning={"recommended": True, "deadline": "24h"},
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": True, "deadline": "24h"},
                "triggered_criteria": [], "competent_authority": "ILR",
                "csirt": "CIRCL", "notification_recipient": "ILR",
            }],
        )
        Submission.objects.create(
            assessment=self.assessment, target="early_warning", status="success",
        )
        Submission.objects.create(
            assessment=self.assessment, target="misp_push", status="success",
            misp_event_id="42",
        )
        self.client = Client()
        self.client.login(username="ewstatus", password="testpass123")

    def test_status_card_shows_acknowledged(self):
        with patch("entity.views.get_event_tags") as mock_tags:
            mock_tags.return_value = [
                'cyberscale:notification-status="acknowledged"',
                'nis2:notification-stage="early-warning"',
                "tlp:amber",
            ]
            resp = self.client.get(f"/assess/{self.assessment.pk}/")

        assert resp.status_code == 200
        assert b"ACKNOWLEDGED" in resp.content

    def test_status_card_shows_support_dispatched(self):
        with patch("entity.views.get_event_tags") as mock_tags:
            mock_tags.return_value = [
                'cyberscale:notification-status="support-dispatched"',
                'cyberscale:support-requested="true"',
            ]
            resp = self.client.get(f"/assess/{self.assessment.pk}/")

        assert resp.status_code == 200
        assert b"SUPPORT-DISPATCHED" in resp.content

    def test_status_card_graceful_when_misp_unavailable(self):
        with patch("entity.views.get_event_tags") as mock_tags:
            mock_tags.return_value = []
            resp = self.client.get(f"/assess/{self.assessment.pk}/")

        assert resp.status_code == 200
        # Should not crash, show unavailable or empty
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py::EarlyWarningStatusTest -v`
Expected: FAIL — status card not rendered

- [ ] **Step 3: Update assessment_result_view to query MISP status**

In `entity/views.py`, update `assessment_result_view`:

```python
@login_required
def assessment_result_view(request, pk):
    entity = _get_entity_or_redirect(request)
    if entity is None:
        return redirect("register")
    assessment = get_object_or_404(Assessment, pk=pk, entity=entity)

    ew_submitted = assessment.submissions.filter(target="early_warning", status="success").exists()
    ew_recommended = assessment.result_early_warning.get("recommended", False)

    # Query MISP for early warning status
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
```

- [ ] **Step 4: Update assessment_result.html status card**

Replace the early warning block (added in Task 4 step 6) with:

```html
{# Early warning status / submit button #}
{% if ew_submitted %}
<div class="cs-card">
  <h3>Early Warning Status</h3>
  {% if ew_status %}
    <p><span class="badge badge-model">{{ ew_status|upper }}</span></p>
  {% else %}
    <p><span class="badge badge-undetermined">STATUS UNAVAILABLE</span></p>
  {% endif %}
  {% if ew_support_requested %}
    <p><strong>CSIRT Support:</strong> Requested</p>
  {% endif %}
  <p><small>Submitted. Follow up with incident notification within 72 hours per Art. 23(4)(b).</small></p>
</div>
{% elif ew_recommended %}
<div class="cs-card" style="border-left: 3px solid var(--cs-significant);">
  <h3>Early Warning Recommended</h3>
  <p>Deadline: {{ assessment.result_early_warning.deadline }} from awareness</p>
  <a href="{% url 'early_warning' assessment.pk %}" role="button" class="contrast">Submit Early Warning</a>
</div>
{% endif %}
```

- [ ] **Step 5: Run tests**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_early_warning.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add entity/views.py templates/entity/assessment_result.html entity/tests/test_early_warning.py
git commit -m "feat: early warning status card queries MISP tags for lifecycle state"
```

---

### Task 7: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full web test suite**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v --ignore=entity/tests/test_misp_integration.py`
Expected: ALL PASS

- [ ] **Step 2: Run core library tests**

Run: `docker compose exec cyberscale-web python -m pytest src/tests/ -v --ignore=src/tests/test_cwe_enrichment.py --ignore=src/tests/test_generation_balance.py --ignore=src/tests/test_mix_curated.py --ignore=src/tests/test_weighted_loss.py`
Expected: ALL PASS

- [ ] **Step 3: Register MISP template**

Run: `docker compose exec misp /scripts/misp-init.sh`
Expected: "Installed: cyberscale-early-warning"

- [ ] **Step 4: Manual smoke test**

1. Log in as `luxenergy`, run an assessment with high impact → SIGNIFICANT
2. Push assessment to MISP via admin
3. Click "Submit Early Warning" on result page
4. Fill form, submit → verify success
5. Check MISP: assessment event has `cyberscale-early-warning` object + tags
6. Admin: select assessment → "Acknowledge early warning"
7. Entity result page: status shows "ACKNOWLEDGED"
8. Admin: "Close early warning"
9. Entity: status shows "CLOSED"

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: smoke test adjustments for early warning"
```
