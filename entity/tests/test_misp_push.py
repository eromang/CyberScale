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
        self.assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Profile push test", sector="energy",
            entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
        )
        self.client = Client()
        self.client.login(username="admin", password="adminpass123")

    def test_push_profile_success(self):
        with patch("entity.misp_push.push_event") as mock_push:
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
        with patch("entity.misp_push.push_event") as mock_push:
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
