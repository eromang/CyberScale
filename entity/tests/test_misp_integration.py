"""Integration tests against a real MISP instance in Docker.

These tests require the MISP container to be running with a valid API key.
Set MISP_URL and MISP_API_KEY environment variables before running.

Run with: docker compose exec -e MISP_URL=https://misp -e MISP_API_KEY=<key> cyberscale-web python -m pytest entity/tests/test_misp_integration.py -v
"""

import os
import uuid

import pytest
from django.contrib.auth.models import User
from django.test import TestCase

from entity.models import Assessment, Entity, EntityType


MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")

_PLACEHOLDER_KEYS = {"changeme-run-misp-authkey-setup", "cyberscale-misp-test-api-key", ""}

requires_misp = pytest.mark.skipif(
    not MISP_URL or MISP_API_KEY in _PLACEHOLDER_KEYS,
    reason="MISP_URL and MISP_API_KEY not set (or placeholder key)",
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
        result = push_event(MISP_URL, MISP_API_KEY, event_dict, ssl=False)

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
        profile_result = push_event(MISP_URL, MISP_API_KEY, profile_dict, ssl=False)
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
        result = push_event(MISP_URL, MISP_API_KEY, event_dict, ssl=False)

        assert result["success"] is True, f"Push failed: {result['error']}"
        assert result["event_id"]

    def test_push_with_bad_credentials_fails(self):
        from entity.misp_push import push_event

        result = push_event(MISP_URL, "invalid-key-that-is-40-chars-long-xxxxx", {"Event": {"info": "Bad", "Tag": [], "Object": []}}, ssl=False)
        assert result["success"] is False
