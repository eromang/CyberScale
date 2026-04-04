"""Tests for authority and CSIRT registry."""

from django.contrib.auth.models import User
from django.db import IntegrityError
from django.test import TestCase

from entity.models import CompetentAuthority, CSIRT, Entity, EntityType


class CompetentAuthorityModelTest(TestCase):
    def test_create_ca(self):
        ca = CompetentAuthority.objects.create(
            name="Institut Luxembourgeois de Régulation",
            abbreviation="ILR",
            ms="LU",
            sectors=["energy", "transport"],
            website="https://web.ilr.lu",
            receives_notifications=True,
        )
        assert ca.abbreviation == "ILR"
        assert ca.ms == "LU"
        assert ca.receives_notifications is True

    def test_ca_unique_together(self):
        CompetentAuthority.objects.create(abbreviation="ILR", name="ILR", ms="LU")
        with self.assertRaises(IntegrityError):
            CompetentAuthority.objects.create(abbreviation="ILR", name="ILR duplicate", ms="LU")

    def test_ca_str(self):
        ca = CompetentAuthority.objects.create(abbreviation="ILR", name="ILR", ms="LU")
        assert "ILR" in str(ca)
        assert "LU" in str(ca)


class CSIRTModelTest(TestCase):
    def test_create_csirt(self):
        csirt = CSIRT.objects.create(
            name="CIRCL",
            abbreviation="CIRCL",
            ms="LU",
            website="https://www.circl.lu",
            contact_email="info@circl.lu",
            emergency_phone="+352 247 88444",
            receives_notifications=False,
        )
        assert csirt.abbreviation == "CIRCL"
        assert csirt.emergency_phone == "+352 247 88444"
        assert csirt.receives_notifications is False

    def test_csirt_unique_together(self):
        CSIRT.objects.create(abbreviation="CIRCL", name="CIRCL", ms="LU")
        with self.assertRaises(IntegrityError):
            CSIRT.objects.create(abbreviation="CIRCL", name="CIRCL dup", ms="LU")

    def test_csirt_str(self):
        csirt = CSIRT.objects.create(abbreviation="CIRCL", name="CIRCL", ms="LU")
        assert "CIRCL" in str(csirt)


class EntityTypeFKTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("fktest", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="FK Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )
        self.ca = CompetentAuthority.objects.create(
            abbreviation="ILR", name="ILR", ms="LU", sectors=["energy"],
            receives_notifications=True,
        )
        self.csirt = CSIRT.objects.create(
            abbreviation="CIRCL", name="CIRCL", ms="LU",
            receives_notifications=False,
        )

    def test_entitytype_fk_assignment(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy",
            entity_type="electricity_undertaking",
            competent_authority=self.ca, csirt=self.csirt,
        )
        assert et.competent_authority.abbreviation == "ILR"
        assert et.csirt.abbreviation == "CIRCL"
        assert et.ca_auto_assigned is True
        assert et.csirt_auto_assigned is True

    def test_entitytype_fk_nullable(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy",
            entity_type="electricity_undertaking",
        )
        assert et.competent_authority is None
        assert et.csirt is None

    def test_ca_delete_sets_null(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy",
            entity_type="electricity_undertaking",
            competent_authority=self.ca,
        )
        self.ca.delete()
        et.refresh_from_db()
        assert et.competent_authority is None
