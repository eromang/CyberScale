"""Smoke tests for entity views."""

from django.contrib.auth.models import User
from django.test import Client, TestCase

from entity.models import Assessment, Entity, EntityType


class AuthViewsTest(TestCase):
    def test_login_page_loads(self):
        resp = self.client.get("/login/")
        assert resp.status_code == 200
        assert b"Login" in resp.content

    def test_register_page_loads(self):
        resp = self.client.get("/register/")
        assert resp.status_code == 200
        assert b"Registration" in resp.content

    def test_dashboard_requires_login(self):
        resp = self.client.get("/")
        assert resp.status_code == 302
        assert "/login/" in resp.url

    def test_register_creates_entity(self):
        resp = self.client.post("/register/", {
            "username": "newuser",
            "password1": "SecurePass123!",
            "password2": "SecurePass123!",
            "organisation_name": "New Corp",
            "sector": "energy",
            "entity_type": "electricity_undertaking",
            "ms_established": "LU",
        })
        assert resp.status_code == 302
        assert Entity.objects.filter(organisation_name="New Corp").exists()
        assert EntityType.objects.filter(entity_type="electricity_undertaking").exists()


class DashboardViewTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("testuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Test Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.client.login(username="testuser", password="testpass123")

    def test_dashboard_loads(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert b"Test Corp" in resp.content

    def test_dashboard_no_entity_redirects(self):
        user2 = User.objects.create_user("noentity", password="testpass123")
        c = Client()
        c.login(username="noentity", password="testpass123")
        resp = c.get("/")
        assert resp.status_code == 302
        assert "/register/" in resp.url

    def test_assessment_form_loads(self):
        resp = self.client.get("/assess/")
        assert resp.status_code == 200
        assert b"Incident Assessment" in resp.content

    def test_logout_redirects(self):
        resp = self.client.get("/logout/")
        assert resp.status_code == 302


class AssessmentFlowTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("testuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Test Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )
        EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        self.client.login(username="testuser", password="testpass123")

    def test_save_draft(self):
        resp = self.client.post("/assess/", {
            "description": "Test draft",
            "affected_entity_types": ["energy:electricity_undertaking"],
            "save_draft": "",
            "impact_0_type": "energy:electricity_undertaking",
            "impact_0_service_impact": "none",
            "impact_0_data_impact": "none",
            "impact_0_safety_impact": "none",
            "impact_0_financial_impact": "none",
            "impact_0_affected_persons_count": "0",
            "impact_0_impact_duration_hours": "0",
        })
        assert resp.status_code == 302
        assert Assessment.objects.filter(status="draft").exists()

    def test_run_assessment(self):
        resp = self.client.post("/assess/", {
            "description": "SCADA compromise at electricity provider",
            "affected_entity_types": ["energy:electricity_undertaking"],
            "suspected_malicious": "on",
            "run_assessment": "",
            "impact_0_type": "energy:electricity_undertaking",
            "impact_0_ms_affected": ["LU"],
            "impact_0_service_impact": "unavailable",
            "impact_0_data_impact": "compromised",
            "impact_0_safety_impact": "health_risk",
            "impact_0_financial_impact": "significant",
            "impact_0_affected_persons_count": "50000",
            "impact_0_impact_duration_hours": "4",
        })
        assert resp.status_code == 302
        a = Assessment.objects.filter(status="completed").first()
        assert a is not None
        assert a.result_significance_label in ("SIGNIFICANT", "LIKELY", "NOT SIGNIFICANT", "UNLIKELY", "UNDETERMINED")
        assert len(a.assessment_results) == 1
        assert len(a.per_type_impacts) == 1

    def test_result_page_loads(self):
        # Create a completed assessment first
        a = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test", sector="energy", entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            assessment_results=[{"sector": "energy", "entity_type": "electricity_undertaking",
                                 "significance_label": "SIGNIFICANT", "model": "test"}],
        )
        resp = self.client.get(f"/assess/{a.pk}/")
        assert resp.status_code == 200
        assert b"SIGNIFICANT" in resp.content

    def test_delete_draft(self):
        a = Assessment.objects.create(
            entity=self.entity, status="draft",
            description="To delete", sector="energy", entity_type="electricity_undertaking",
        )
        resp = self.client.post(f"/assess/draft/{a.pk}/delete/")
        assert resp.status_code == 302
        assert not Assessment.objects.filter(pk=a.pk).exists()

    def test_cannot_delete_completed(self):
        a = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Completed", sector="energy", entity_type="electricity_undertaking",
        )
        resp = self.client.post(f"/assess/draft/{a.pk}/delete/")
        assert resp.status_code == 404


class HTMXEndpointsTest(TestCase):
    def test_entity_types_for_sector(self):
        resp = self.client.get("/htmx/entity-types/?sector=energy")
        assert resp.status_code == 200
        assert b"electricity_undertaking" in resp.content

    def test_impact_fields_endpoint(self):
        resp = self.client.get("/htmx/impact-fields/?types=energy:electricity_undertaking")
        assert resp.status_code == 200
        assert b"impact_0_service_impact" in resp.content
        assert b"Electricity (LU)" in resp.content

    def test_impact_fields_no_types(self):
        resp = self.client.get("/htmx/impact-fields/")
        assert resp.status_code == 200
        assert resp.content == b""
