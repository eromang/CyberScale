"""Tests for authority and CSIRT registry."""

from django.contrib.auth.models import User
from django.core.management import call_command
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


class SeedAuthoritiesTest(TestCase):
    def test_seed_creates_authorities(self):
        call_command("seed_authorities")
        assert CompetentAuthority.objects.filter(abbreviation="ILR", ms="LU").exists()
        assert CompetentAuthority.objects.filter(abbreviation="CSSF", ms="LU").exists()
        assert CompetentAuthority.objects.filter(abbreviation="CCB", ms="BE").exists()
        assert CompetentAuthority.objects.filter(abbreviation="BNB", ms="BE").exists()

    def test_seed_creates_csirts(self):
        call_command("seed_authorities")
        assert CSIRT.objects.filter(abbreviation="CIRCL", ms="LU").exists()
        assert CSIRT.objects.filter(abbreviation="GOVCERT.LU", ms="LU").exists()
        assert CSIRT.objects.filter(abbreviation="CERT.be", ms="BE").exists()

    def test_seed_idempotent(self):
        call_command("seed_authorities")
        count_ca = CompetentAuthority.objects.count()
        count_csirt = CSIRT.objects.count()
        call_command("seed_authorities")
        assert CompetentAuthority.objects.count() == count_ca
        assert CSIRT.objects.count() == count_csirt

    def test_seed_updates_contact(self):
        CompetentAuthority.objects.create(
            abbreviation="ILR", name="Old Name", ms="LU",
            sectors=["energy"], receives_notifications=False,
        )
        call_command("seed_authorities")
        ilr = CompetentAuthority.objects.get(abbreviation="ILR", ms="LU")
        assert ilr.name == "Institut Luxembourgeois de Régulation"
        assert ilr.receives_notifications is True

    def test_seed_notification_flags(self):
        call_command("seed_authorities")
        ilr = CompetentAuthority.objects.get(abbreviation="ILR", ms="LU")
        assert ilr.receives_notifications is True
        circl = CSIRT.objects.get(abbreviation="CIRCL", ms="LU")
        assert circl.receives_notifications is False
        cert_be = CSIRT.objects.get(abbreviation="CERT.be", ms="BE")
        assert cert_be.receives_notifications is True
