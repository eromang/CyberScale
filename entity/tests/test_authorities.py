"""Tests for authority and CSIRT registry."""

from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase

from entity.models import Assessment, CompetentAuthority, CSIRT, Entity, EntityType
from entity.authority import assign_authority


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


class AutoAssignmentTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("assigntest", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="Assign Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )

    def test_assign_lu_energy(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "ILR"
        assert et.csirt.abbreviation == "CIRCL"
        assert et.ca_auto_assigned is True
        assert et.csirt_auto_assigned is True

    def test_assign_lu_banking_gets_cssf(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="banking", entity_type="credit_institution",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "CSSF"

    def test_assign_be_energy_gets_ccb(self):
        user2 = User.objects.create_user("beuser", password="testpass123")
        be_entity = Entity.objects.create(
            user=user2, organisation_name="BE Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="BE",
        )
        et = EntityType.objects.create(
            entity=be_entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "CCB"
        assert et.csirt.abbreviation == "CERT.be"

    def test_assign_be_banking_gets_bnb(self):
        user3 = User.objects.create_user("bebank", password="testpass123")
        be_entity = Entity.objects.create(
            user=user3, organisation_name="BE Bank",
            sector="banking", entity_type="credit_institution",
            ms_established="BE",
        )
        et = EntityType.objects.create(
            entity=be_entity, sector="banking", entity_type="credit_institution",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "BNB"

    def test_specific_sector_wins_over_wildcard(self):
        user4 = User.objects.create_user("priority", password="testpass123")
        be_entity = Entity.objects.create(
            user=user4, organisation_name="Priority Bank",
            sector="banking", entity_type="credit_institution",
            ms_established="BE",
        )
        et = EntityType.objects.create(
            entity=be_entity, sector="banking", entity_type="credit_institution",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "BNB"

    def test_unknown_ms_no_assignment(self):
        user5 = User.objects.create_user("fruser", password="testpass123")
        fr_entity = Entity.objects.create(
            user=user5, organisation_name="FR Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="FR",
        )
        et = EntityType.objects.create(
            entity=fr_entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority is None
        assert et.csirt is None

    def test_manual_override_persists(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "ILR"

        cssf = CompetentAuthority.objects.get(abbreviation="CSSF", ms="LU")
        et.competent_authority = cssf
        et.ca_auto_assigned = False
        et.save()

        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "CSSF"
        assert et.ca_auto_assigned is False


class AssessmentAuthorityTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("assessauth", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="Assess Auth Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )
        self.et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(self.et)

    def test_assessment_reads_ca_from_fk(self):
        from entity.assessment import run_entity_assessment
        result = run_entity_assessment(
            description="Test incident",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            service_impact="degraded",
            entity_type_obj=self.et,
        )
        assert result["competent_authority"] == "ILR"
        assert result["csirt"] == "CIRCL"

    def test_assessment_includes_notification_recipient(self):
        from entity.assessment import run_entity_assessment
        result = run_entity_assessment(
            description="Test incident",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            service_impact="degraded",
            entity_type_obj=self.et,
        )
        assert result["notification_recipient"] == "ILR"

    def test_assessment_no_authority_fallback(self):
        from entity.assessment import run_entity_assessment
        result = run_entity_assessment(
            description="Test incident",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            service_impact="degraded",
            entity_type_obj=None,
        )
        # Falls back to hardcoded _determine_competent_authority
        assert result["competent_authority"] == "ILR"

    def test_assessment_authority_override_flag(self):
        from entity.assessment import run_entity_assessment
        self.et.ca_auto_assigned = False
        self.et.save()
        result = run_entity_assessment(
            description="Test incident",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            service_impact="degraded",
            entity_type_obj=self.et,
        )
        assert result["authority_override"] is True


from django.test import Client as TestClient


class AdminAuthorityTest(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser("authadmin", "admin@test.com", "adminpass123")
        self.client = TestClient()
        self.client.login(username="authadmin", password="adminpass123")
        call_command("seed_authorities")

    def test_ca_admin_loads(self):
        resp = self.client.get("/admin/entity/competentauthority/")
        assert resp.status_code == 200
        assert b"ILR" in resp.content

    def test_csirt_admin_loads(self):
        resp = self.client.get("/admin/entity/csirt/")
        assert resp.status_code == 200
        assert b"CIRCL" in resp.content

    def test_entitytype_admin_shows_authority(self):
        user = User.objects.create_user("etadmin", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="ET Admin Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )
        et = EntityType.objects.create(
            entity=entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        resp = self.client.get("/admin/entity/entitytype/")
        assert resp.status_code == 200
        assert b"ILR" in resp.content


class MISPExportAuthorityTest(TestCase):
    def test_misp_export_includes_csirt(self):
        from entity.misp_export import build_misp_event_global

        user = User.objects.create_user("mispauth", password="testpass123")
        entity = Entity.objects.create(
            user=user, organisation_name="MISP Auth Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
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
                "competent_authority": "ILR",
                "csirt": "CIRCL",
                "notification_recipient": "ILR",
            }],
        )

        event = build_misp_event_global(assessment, entity)
        obj = event["Event"]["Object"][0]
        attrs = {a["object_relation"]: a["value"] for a in obj["Attribute"]}
        assert attrs.get("csirt") == "CIRCL"
        assert attrs.get("notification-recipient") == "ILR"


class UIAuthorityTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("uitest", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="UI Auth Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )
        self.et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(self.et)
        self.client = TestClient()
        self.client.login(username="uitest", password="testpass123")

    def test_dashboard_shows_authority(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert b"ILR" in resp.content
        assert b"CIRCL" in resp.content

    def test_result_page_shows_notification_recipient(self):
        assessment = Assessment.objects.create(
            entity=self.entity, status="completed",
            description="Test", sector="energy", entity_type="electricity_undertaking",
            result_significance_label="SIGNIFICANT",
            result_competent_authority="ILR",
            assessment_results=[{
                "sector": "energy", "entity_type": "electricity_undertaking",
                "significance_label": "SIGNIFICANT", "model": "ir_thresholds",
                "early_warning": {"recommended": True, "deadline": "24h"},
                "triggered_criteria": [],
                "competent_authority": "ILR",
                "csirt": "CIRCL",
                "notification_recipient": "ILR",
            }],
        )
        resp = self.client.get(f"/assess/{assessment.pk}/")
        assert resp.status_code == 200
        assert b"ILR" in resp.content


class CERDesignationTest(TestCase):
    def setUp(self):
        call_command("seed_authorities")
        self.user = User.objects.create_user("certest", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user, organisation_name="CER Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
            cer_designated=False,
        )

    def test_non_cer_gets_circl(self):
        et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.csirt.abbreviation == "CIRCL"

    def test_cer_designated_gets_govcert(self):
        self.entity.cer_designated = True
        self.entity.save()
        et = EntityType.objects.create(
            entity=self.entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.csirt.abbreviation == "GOVCERT.LU"

    def test_cer_only_affects_lu(self):
        user2 = User.objects.create_user("cerbe", password="testpass123")
        be_entity = Entity.objects.create(
            user=user2, organisation_name="CER BE Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="BE",
            cer_designated=True,
        )
        et = EntityType.objects.create(
            entity=be_entity, sector="energy", entity_type="electricity_undertaking",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.csirt.abbreviation == "CERT.be"

    def test_cer_default_false(self):
        user3 = User.objects.create_user("cerdefault", password="testpass123")
        entity = Entity.objects.create(
            user=user3, organisation_name="Default Corp",
            sector="energy", entity_type="electricity_undertaking",
            ms_established="LU",
        )
        assert entity.cer_designated is False

    def test_public_administration_gets_govcert(self):
        user4 = User.objects.create_user("pubadmin", password="testpass123")
        entity = Entity.objects.create(
            user=user4, organisation_name="Ministry of Digital",
            sector="public_administration", entity_type="central_government_entity",
            ms_established="LU",
        )
        et = EntityType.objects.create(
            entity=entity, sector="public_administration",
            entity_type="central_government_entity",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.csirt.abbreviation == "GOVCERT.LU"

    def test_public_administration_be_not_affected(self):
        user5 = User.objects.create_user("pubadminbe", password="testpass123")
        entity = Entity.objects.create(
            user=user5, organisation_name="BE Ministry",
            sector="public_administration", entity_type="central_government_entity",
            ms_established="BE",
        )
        et = EntityType.objects.create(
            entity=entity, sector="public_administration",
            entity_type="central_government_entity",
        )
        assign_authority(et)
        et.refresh_from_db()
        assert et.csirt.abbreviation == "CERT.be"
