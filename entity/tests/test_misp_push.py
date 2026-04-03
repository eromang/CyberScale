"""Tests for MISP push module and view."""

from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.test import Client, TestCase

from entity.models import Assessment, Entity, EntityType, Submission


class MISPPushModuleTest(TestCase):
    """Tests for entity.misp_push.push_event."""

    def test_push_event_success(self):
        from entity.misp_push import push_event

        mock_event = MagicMock()
        mock_event.id = 42
        mock_event.uuid = "abc-123"

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.add_event.return_value = mock_event

            result = push_event(
                "https://misp.example.org", "test-api-key",
                {"Event": {"info": "Test", "uuid": "ev-uuid", "Tag": [], "Object": []}},
            )

        assert result["success"] is True
        assert result["event_id"] == "42"
        assert result["event_uuid"] == "abc-123"
        assert result["error"] is None

    def test_push_event_connection_failure(self):
        from entity.misp_push import push_event

        with patch("entity.misp_push.PyMISP", side_effect=Exception("Connection refused")):
            result = push_event("https://bad.example.org", "key", {"Event": {}})

        assert result["success"] is False
        assert "Connection refused" in result["error"]

    def test_push_event_api_error(self):
        from entity.misp_push import push_event

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.add_event.return_value = {"errors": ["403 Forbidden"]}

            result = push_event(
                "https://misp.example.org", "key",
                {"Event": {"info": "Test", "uuid": "ev-uuid", "Tag": [], "Object": []}},
            )

        assert result["success"] is False
        assert "403" in result["error"]

    def test_push_event_exception_during_push(self):
        from entity.misp_push import push_event

        with patch("entity.misp_push.PyMISP") as MockPyMISP:
            instance = MockPyMISP.return_value
            instance.add_event.side_effect = Exception("Timeout")

            result = push_event(
                "https://misp.example.org", "key",
                {"Event": {"info": "Test", "uuid": "ev-uuid", "Tag": [], "Object": []}},
            )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_dict_to_misp_event(self):
        from entity.misp_push import _dict_to_misp_event

        event_data = {
            "info": "CyberScale test",
            "date": "2026-04-03",
            "threat_level_id": "1",
            "analysis": "2",
            "distribution": "1",
            "uuid": "test-uuid",
            "Tag": [{"name": "tlp:amber"}],
            "Object": [
                {
                    "name": "cyberscale-entity-assessment",
                    "uuid": "obj-uuid",
                    "Attribute": [
                        {"object_relation": "sector", "type": "text", "value": "energy"},
                    ],
                }
            ],
        }

        misp_event = _dict_to_misp_event(event_data)
        assert misp_event.info == "CyberScale test"
        assert str(misp_event.uuid) == "test-uuid"
        assert len(misp_event.Object) == 1
        assert len(misp_event.Object[0].Attribute) == 1


class MISPPushViewTest(TestCase):
    """Tests for the MISP push view endpoint."""

    def setUp(self):
        self.user = User.objects.create_user("testuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Test Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            misp_instance_url="https://misp.example.org",
            misp_api_key="test-api-key",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.assessment = Assessment.objects.create(
            entity=self.entity,
            status="completed",
            description="Test incident",
            sector="energy",
            entity_type="electricity_undertaking",
            result_significance=True,
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
            }],
        )
        self.client.login(username="testuser", password="testpass123")

    def test_push_requires_post(self):
        resp = self.client.get(f"/assess/{self.assessment.pk}/misp-push/")
        assert resp.status_code == 405

    def test_push_requires_login(self):
        c = Client()
        resp = c.post(f"/assess/{self.assessment.pk}/misp-push/")
        assert resp.status_code == 302
        assert "/login/" in resp.url

    def test_push_success(self):
        mock_event = MagicMock()
        mock_event.id = 99
        mock_event.uuid = "pushed-uuid"

        with patch("entity.misp_push.push_event") as mock_push:
            mock_push.return_value = {
                "success": True, "event_id": "99",
                "event_uuid": "pushed-uuid", "error": None,
            }
            resp = self.client.post(f"/assess/{self.assessment.pk}/misp-push/")

        assert resp.status_code == 302
        sub = Submission.objects.filter(target="misp_push", status="success").first()
        assert sub is not None
        assert sub.misp_event_id == "99"

    def test_push_failure_records_submission(self):
        with patch("entity.misp_push.push_event") as mock_push:
            mock_push.return_value = {
                "success": False, "event_id": None,
                "event_uuid": None, "error": "Connection refused",
            }
            resp = self.client.post(f"/assess/{self.assessment.pk}/misp-push/")

        assert resp.status_code == 302
        sub = Submission.objects.filter(target="misp_push", status="failed").first()
        assert sub is not None

    def test_push_without_misp_config(self):
        self.entity.misp_instance_url = ""
        self.entity.misp_api_key = ""
        self.entity.save()

        resp = self.client.post(f"/assess/{self.assessment.pk}/misp-push/")
        assert resp.status_code == 302
        assert not Submission.objects.filter(target="misp_push").exists()

    def test_push_draft_returns_404(self):
        draft = Assessment.objects.create(
            entity=self.entity, status="draft",
            description="Draft", sector="energy", entity_type="electricity_undertaking",
        )
        resp = self.client.post(f"/assess/{draft.pk}/misp-push/")
        assert resp.status_code == 404

    def test_push_button_visible_when_configured(self):
        resp = self.client.get(f"/assess/{self.assessment.pk}/")
        assert b"Push to MISP" in resp.content

    def test_push_button_hidden_without_config(self):
        self.entity.misp_instance_url = ""
        self.entity.save()
        resp = self.client.get(f"/assess/{self.assessment.pk}/")
        assert b"Push to MISP" not in resp.content


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
