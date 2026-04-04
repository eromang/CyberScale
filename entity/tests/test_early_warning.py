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
