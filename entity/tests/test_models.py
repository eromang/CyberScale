"""Smoke tests for entity models."""

from django.contrib.auth.models import User
from django.test import TestCase

from entity.models import Assessment, Entity, EntityType, Submission


class EntityModelTest(TestCase):
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
            entity=self.entity,
            sector="energy",
            entity_type="electricity_undertaking",
        )

    def test_entity_str(self):
        assert "Test Corp" in str(self.entity)

    def test_entity_type_label(self):
        et = self.entity.entity_types.first()
        assert et.sector_label == "Energy"
        assert "Electricity" in et.label or "electricity" in et.label.lower()

    def test_entity_type_unique_together(self):
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            EntityType.objects.create(
                entity=self.entity,
                sector="energy",
                entity_type="electricity_undertaking",
            )

    def test_multiple_entity_types(self):
        EntityType.objects.create(
            entity=self.entity,
            sector="drinking_water",
            entity_type="drinking_water_supplier",
        )
        assert self.entity.entity_types.count() == 2


class AssessmentModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("testuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Test Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )

    def test_create_draft(self):
        a = Assessment.objects.create(
            entity=self.entity,
            status="draft",
            description="Test draft",
            sector="energy",
            entity_type="electricity_undertaking",
        )
        assert a.status == "draft"
        assert a.result_significance is None

    def test_per_type_impacts_default(self):
        a = Assessment.objects.create(
            entity=self.entity,
            status="draft",
            description="Test",
            sector="energy",
            entity_type="electricity_undertaking",
        )
        assert a.per_type_impacts == []
        assert a.affected_entity_types == []
        assert a.assessment_results == []

    def test_assessment_ordering(self):
        a1 = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="First", sector="energy", entity_type="electricity_undertaking",
        )
        a2 = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Second", sector="energy", entity_type="electricity_undertaking",
        )
        assessments = list(self.entity.assessments.all())
        assert assessments[0].pk == a2.pk  # most recent first


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
