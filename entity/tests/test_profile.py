"""Tests for entity profile editing and CIDR validation."""

import ipaddress

from django.contrib.auth.models import User
from django.test import Client, TestCase

from entity.forms import EntityProfileForm
from entity.models import Entity


class EntityProfileFormTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("profuser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Profile Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )

    def test_form_loads_with_instance(self):
        form = EntityProfileForm(instance=self.entity)
        assert "organisation_name" in form.fields
        assert "address" in form.fields
        assert "ip_ranges" in form.fields
        assert "ms_services" in form.fields

    def test_valid_cidr_accepted(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "192.168.1.0/24\n10.0.0.0/8\n2001:db8::/32",
                "ms_services": ["LU", "BE"],
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ip_ranges == ["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]

    def test_invalid_cidr_rejected(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "192.168.1.0/24\nnot-a-cidr\n999.999.999.999/99",
            },
        )
        assert not form.is_valid()
        assert "ip_ranges" in form.errors

    def test_empty_ip_ranges_valid(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={"organisation_name": "Profile Corp", "ip_ranges": ""},
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ip_ranges == []

    def test_ms_services_saved_as_list(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Profile Corp",
                "ip_ranges": "",
                "ms_services": ["LU", "DE", "FR"],
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.ms_services == ["LU", "DE", "FR"]

    def test_all_art27_fields_saved(self):
        form = EntityProfileForm(
            instance=self.entity,
            data={
                "organisation_name": "Updated Corp",
                "address": "1 Rue NIS2",
                "contact_email": "sec@corp.lu",
                "contact_phone": "+352 111",
                "responsible_person_name": "Alice",
                "responsible_person_email": "alice@corp.lu",
                "technical_contact_name": "Bob",
                "technical_contact_email": "bob@corp.lu",
                "technical_contact_phone": "+352 222",
                "ip_ranges": "10.0.0.0/8",
                "ms_services": ["LU"],
                "misp_instance_url": "",
                "misp_api_key": "",
                "misp_default_tlp": "tlp:amber",
            },
        )
        assert form.is_valid(), form.errors
        entity = form.save()
        assert entity.organisation_name == "Updated Corp"
        assert entity.address == "1 Rue NIS2"
        assert entity.technical_contact_name == "Bob"


class ProfileEditViewTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("edituser", password="testpass123")
        self.entity = Entity.objects.create(
            user=self.user,
            organisation_name="Edit Corp",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
        )
        self.client = Client()
        self.client.login(username="edituser", password="testpass123")

    def test_profile_edit_loads(self):
        resp = self.client.get("/profile/edit/")
        assert resp.status_code == 200
        assert b"Edit Corp" in resp.content
        assert b"Organisation" in resp.content

    def test_profile_edit_requires_login(self):
        c = Client()
        resp = c.get("/profile/edit/")
        assert resp.status_code == 302
        assert "/login/" in resp.url

    def test_profile_edit_saves(self):
        resp = self.client.post("/profile/edit/", {
            "organisation_name": "Updated Corp",
            "address": "1 Rue NIS2",
            "contact_email": "sec@corp.lu",
            "ip_ranges": "10.0.0.0/8",
            "ms_services": ["LU", "BE"],
            "misp_default_tlp": "tlp:amber",
        })
        assert resp.status_code == 302
        self.entity.refresh_from_db()
        assert self.entity.organisation_name == "Updated Corp"
        assert self.entity.address == "1 Rue NIS2"
        assert self.entity.ip_ranges == ["10.0.0.0/8"]
        assert self.entity.ms_services == ["LU", "BE"]

    def test_dashboard_has_edit_profile_link(self):
        resp = self.client.get("/")
        assert b"/profile/edit/" in resp.content
