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

    def test_add_object_connection_failure(self):
        from entity.misp_push import add_object_to_event

        with patch("entity.misp_push.PyMISP", side_effect=Exception("Connection refused")):
            result = add_object_to_event("https://bad.example.org", "key", "5", {})

        assert result["success"] is False
        assert "Connection refused" in result["error"]

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

    def test_update_event_tags_add_only(self):
        from entity.misp_push import update_event_tags

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.direct_call.side_effect = [
                {"Event": {"Tag": []}},
                {"saved": True},
            ]

            result = update_event_tags(
                "https://misp.example.org", "key", "5",
                add_tag='nis2:notification-stage="early-warning"',
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

    def test_get_event_tags_returns_empty_on_failure(self):
        from entity.misp_push import get_event_tags

        with patch("entity.misp_push.PyMISP", side_effect=Exception("fail")):
            tags = get_event_tags("https://bad.example.org", "key", "5")

        assert tags == []


class EarlyWarningFormTest(TestCase):
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
        # Need a misp_push submission so the view can find the event_id
        Submission.objects.create(
            assessment=self.assessment, target="misp_push", status="success",
            misp_event_id="42",
        )

        with patch("entity.misp_push.add_object_to_event") as mock_add, \
             patch("entity.misp_push.update_event_tags") as mock_tags:
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
        with patch("entity.misp_push.update_event_tags") as mock_tags:
            mock_tags.return_value = {"success": True, "error": None}
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "acknowledge_early_warning",
                "_selected_action": [str(self.assessment.pk)],
            })
        assert resp.status_code == 302
        mock_tags.assert_called()

    def test_close_action(self):
        with patch("entity.misp_push.update_event_tags") as mock_tags:
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
        with patch("entity.misp_push.update_event_tags") as mock_tags:
            resp = self.client.post("/admin/entity/assessment/", {
                "action": "acknowledge_early_warning",
                "_selected_action": [str(no_ew.pk)],
            })
        assert resp.status_code == 302
        mock_tags.assert_not_called()
