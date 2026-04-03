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
