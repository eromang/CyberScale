# Authority & CSIRT Registry (v1.2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce CompetentAuthority and CSIRT models, seed from reference JSON, auto-assign to EntityType records, replace hardcoded authority lookup with FK-based routing, and add CSIRT + notification recipient to assessment results and MISP export.

**Architecture:** Two new Django models (CompetentAuthority, CSIRT) with FKs on EntityType. Reference data in `authorities.json` seeded via management command. Auto-assignment on entity registration with admin override support. Assessment engine reads authority from FK instead of hardcoded function.

**Tech Stack:** Django 5.x, PostgreSQL 16, existing MISP export pipeline

---

## File Structure

| File | Responsibility |
|---|---|
| `entity/models.py` | Add `CompetentAuthority`, `CSIRT` models; add FKs + `auto_assigned` to `EntityType` |
| `entity/migrations/0007_authority_csirt.py` | Migration for new models + EntityType FKs |
| `data/reference/authorities.json` | CA + CSIRT reference data (LU + BE) |
| `entity/authority.py` | New — `assign_authority()` function (auto-assignment logic) |
| `entity/management/commands/seed_authorities.py` | New — load authorities from JSON |
| `entity/management/commands/setup_playground.py` | Add seed + assign to startup chain |
| `entity/assessment.py` | Remove `_determine_competent_authority()`, read from FK, add CSIRT + notification |
| `entity/admin.py` | Add `CompetentAuthorityAdmin`, `CSIRTAdmin`, enhance `EntityTypeAdmin` + inline |
| `entity/views.py` | Call `assign_authority()` on registration + add_entity_type |
| `entity/misp_export.py` | Add `csirt` and `notification-recipient` attributes |
| `data/misp-objects/cyberscale-entity-assessment/definition.json` | Add two new attrs, bump version to 2 |
| `templates/entity/partials/entity_types.html` | Show CA + CSIRT per entity type |
| `templates/entity/assessment_result.html` | Show notification recipient with contact |
| `entity/tests/test_authorities.py` | New — full test suite |

---

### Task 1: CompetentAuthority and CSIRT Models + Migration

**Files:**
- Modify: `entity/models.py`
- Create: `entity/migrations/0007_authority_csirt.py` (auto-generated)
- Test: `entity/tests/test_authorities.py`

- [ ] **Step 1: Write failing tests**

Create `entity/tests/test_authorities.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: FAIL — models do not exist

- [ ] **Step 3: Add models to entity/models.py**

Add before the `Entity` class (after the imports):

```python
class CompetentAuthority(models.Model):
    """NIS2 competent authority (e.g., ILR, CSSF, CCB)."""

    name = models.CharField(max_length=255)
    abbreviation = models.CharField(max_length=20)
    ms = models.CharField(max_length=10)
    sectors = models.JSONField(default=list)
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name_plural = "competent authorities"

    def __str__(self):
        return f"{self.abbreviation} ({self.ms})"


class CSIRT(models.Model):
    """NIS2 CSIRT (e.g., CIRCL, GOVCERT.LU, CERT.be)."""

    name = models.CharField(max_length=255)
    abbreviation = models.CharField(max_length=20)
    ms = models.CharField(max_length=10)
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    emergency_phone = models.CharField(max_length=50, blank=True)
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name = "CSIRT"
        verbose_name_plural = "CSIRTs"

    def __str__(self):
        return f"{self.abbreviation} ({self.ms})"
```

Add to `EntityType` model (after `added_at`):

```python
    competent_authority = models.ForeignKey(
        "CompetentAuthority", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="entity_types",
    )
    csirt = models.ForeignKey(
        "CSIRT", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="entity_types",
    )
    ca_auto_assigned = models.BooleanField(default=True)
    csirt_auto_assigned = models.BooleanField(default=True)
```

- [ ] **Step 4: Generate and apply migration**

Run: `docker compose exec cyberscale-web python manage.py makemigrations entity --name authority_csirt`
Run: `docker compose exec cyberscale-web python manage.py migrate`

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add entity/models.py entity/migrations/0007_authority_csirt.py entity/tests/test_authorities.py
git commit -m "feat: add CompetentAuthority and CSIRT models with EntityType FKs"
```

---

### Task 2: Reference Data + Seed Command

**Files:**
- Create: `data/reference/authorities.json`
- Create: `entity/management/commands/seed_authorities.py`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
from django.core.management import call_command


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::SeedAuthoritiesTest -v`
Expected: FAIL — command does not exist

- [ ] **Step 3: Create authorities.json**

Create `data/reference/authorities.json`:

```json
{
  "version": "1.0",
  "competent_authorities": [
    {
      "abbreviation": "ILR",
      "name": "Institut Luxembourgeois de Régulation",
      "ms": "LU",
      "sectors": ["energy", "transport", "drinking_water", "health",
                   "digital_infrastructure", "ict_service_management",
                   "space", "waste_water", "postal_courier",
                   "chemicals", "food", "manufacturing",
                   "digital_providers", "research"],
      "website": "https://web.ilr.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "CSSF",
      "name": "Commission de Surveillance du Secteur Financier",
      "ms": "LU",
      "sectors": ["banking", "financial_market"],
      "website": "https://www.cssf.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "CCB",
      "name": "Centre for Cybersecurity Belgium",
      "ms": "BE",
      "sectors": ["*"],
      "website": "https://ccb.belgium.be",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "BNB",
      "name": "Banque Nationale de Belgique",
      "ms": "BE",
      "sectors": ["banking", "financial_market"],
      "website": "https://www.nbb.be",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    }
  ],
  "csirts": [
    {
      "abbreviation": "CIRCL",
      "name": "Computer Incident Response Center Luxembourg",
      "ms": "LU",
      "website": "https://www.circl.lu",
      "notification_url": "",
      "contact_email": "info@circl.lu",
      "contact_phone": "",
      "emergency_phone": "+352 247 88444",
      "receives_notifications": false
    },
    {
      "abbreviation": "GOVCERT.LU",
      "name": "GOVCERT.LU",
      "ms": "LU",
      "website": "https://www.govcert.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "emergency_phone": "",
      "receives_notifications": false
    },
    {
      "abbreviation": "CERT.be",
      "name": "CERT.be",
      "ms": "BE",
      "website": "https://cert.be",
      "notification_url": "https://notif.safeonweb.be",
      "contact_email": "cert@cert.be",
      "contact_phone": "",
      "emergency_phone": "+32 2 501 05 60",
      "receives_notifications": true
    }
  ]
}
```

- [ ] **Step 4: Create seed_authorities command**

Create `entity/management/commands/seed_authorities.py`:

```python
"""Seed CompetentAuthority and CSIRT models from authorities.json."""

import json
from pathlib import Path

from django.core.management.base import BaseCommand

from entity.models import CompetentAuthority, CSIRT

REF_FILE = Path(__file__).resolve().parent.parent.parent.parent / "data" / "reference" / "authorities.json"


class Command(BaseCommand):
    help = "Seed competent authorities and CSIRTs from reference data"

    def handle(self, *args, **options):
        with open(REF_FILE, encoding="utf-8") as f:
            data = json.load(f)

        ca_count = 0
        for ca_data in data.get("competent_authorities", []):
            _, created = CompetentAuthority.objects.update_or_create(
                abbreviation=ca_data["abbreviation"],
                ms=ca_data["ms"],
                defaults={
                    "name": ca_data["name"],
                    "sectors": ca_data.get("sectors", []),
                    "website": ca_data.get("website", ""),
                    "notification_url": ca_data.get("notification_url", ""),
                    "contact_email": ca_data.get("contact_email", ""),
                    "contact_phone": ca_data.get("contact_phone", ""),
                    "receives_notifications": ca_data.get("receives_notifications", False),
                },
            )
            ca_count += 1

        csirt_count = 0
        for csirt_data in data.get("csirts", []):
            _, created = CSIRT.objects.update_or_create(
                abbreviation=csirt_data["abbreviation"],
                ms=csirt_data["ms"],
                defaults={
                    "name": csirt_data["name"],
                    "website": csirt_data.get("website", ""),
                    "notification_url": csirt_data.get("notification_url", ""),
                    "contact_email": csirt_data.get("contact_email", ""),
                    "contact_phone": csirt_data.get("contact_phone", ""),
                    "emergency_phone": csirt_data.get("emergency_phone", ""),
                    "receives_notifications": csirt_data.get("receives_notifications", False),
                },
            )
            csirt_count += 1

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {ca_count} competent authorities + {csirt_count} CSIRTs"
        ))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add data/reference/authorities.json entity/management/commands/seed_authorities.py entity/tests/test_authorities.py
git commit -m "feat: add authorities.json reference data and seed_authorities command"
```

---

### Task 3: Auto-Assignment Logic

**Files:**
- Create: `entity/authority.py`
- Modify: `entity/views.py` (register + add_entity_type)
- Modify: `entity/management/commands/setup_playground.py`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
from entity.authority import assign_authority


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
        """BNB (banking) should win over CCB (*) for banking in BE."""
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

        # Admin overrides to CSSF
        cssf = CompetentAuthority.objects.get(abbreviation="CSSF", ms="LU")
        et.competent_authority = cssf
        et.ca_auto_assigned = False
        et.save()

        # Re-assign should NOT overwrite
        assign_authority(et)
        et.refresh_from_db()
        assert et.competent_authority.abbreviation == "CSSF"
        assert et.ca_auto_assigned is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::AutoAssignmentTest -v`
Expected: FAIL — module does not exist

- [ ] **Step 3: Create entity/authority.py**

```python
"""Authority auto-assignment logic for EntityType records."""

from __future__ import annotations

import logging

logger = logging.getLogger("cyberscale.web.authority")


def assign_authority(entity_type) -> None:
    """Auto-assign CompetentAuthority and CSIRT to an EntityType.

    Looks up by sector + entity's ms_established. Skips if manually overridden.
    """
    from .models import CompetentAuthority, CSIRT

    ms = entity_type.entity.ms_established
    sector = entity_type.sector

    if entity_type.ca_auto_assigned:
        ca = _find_ca(ms, sector)
        entity_type.competent_authority = ca
        entity_type.ca_auto_assigned = True

    if entity_type.csirt_auto_assigned:
        csirt = _find_csirt(ms)
        entity_type.csirt = csirt
        entity_type.csirt_auto_assigned = True

    entity_type.save(update_fields=[
        "competent_authority", "csirt", "ca_auto_assigned", "csirt_auto_assigned",
    ])


def _find_ca(ms: str, sector: str):
    """Find the most specific CompetentAuthority for ms + sector."""
    from .models import CompetentAuthority

    candidates = CompetentAuthority.objects.filter(ms=ms)
    exact = [ca for ca in candidates if sector in ca.sectors]
    if exact:
        return exact[0]
    wildcard = [ca for ca in candidates if "*" in ca.sectors]
    if wildcard:
        return wildcard[0]
    return None


def _find_csirt(ms: str):
    """Find the first CSIRT for a given MS."""
    from .models import CSIRT

    return CSIRT.objects.filter(ms=ms).first()
```

- [ ] **Step 4: Hook assign_authority into views**

In `entity/views.py`, in `register_view` after `EntityType.objects.create(...)` (line 87-91), add:

```python
            from .authority import assign_authority
            assign_authority(EntityType.objects.get(entity=entity, entity_type=form.cleaned_data["entity_type"]))
```

In `add_entity_type_view`, after the `get_or_create` call (line 410-412), add:

```python
        et_obj, _ = EntityType.objects.get_or_create(
            entity=entity, entity_type=etype, defaults={"sector": sector}
        )
        from .authority import assign_authority
        assign_authority(et_obj)
```

(Replace the existing `get_or_create` call to capture the object.)

- [ ] **Step 5: Update setup_playground to seed + assign**

In `entity/management/commands/setup_playground.py`, modify `handle()`:

```python
    def handle(self, *args, **options):
        self._seed_authorities()
        self._create_superuser()
        self._check_misp()

    def _seed_authorities(self):
        from django.core.management import call_command
        call_command("seed_authorities")
        # Auto-assign for any EntityType without authority
        from entity.models import EntityType
        from entity.authority import assign_authority
        for et in EntityType.objects.filter(competent_authority__isnull=True, ca_auto_assigned=True):
            assign_authority(et)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add entity/authority.py entity/views.py entity/management/commands/setup_playground.py entity/tests/test_authorities.py
git commit -m "feat: auto-assign authority and CSIRT on entity registration"
```

---

### Task 4: Assessment Engine — FK-Based Authority Lookup

**Files:**
- Modify: `entity/assessment.py`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
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
        et_no_auth = EntityType.objects.create(
            entity=self.entity, sector="food", entity_type="food_producer",
        )
        result = run_entity_assessment(
            description="Test incident",
            sector="food",
            entity_type="food_producer",
            ms_established="LU",
            service_impact="degraded",
            entity_type_obj=et_no_auth,
        )
        # Falls back to ILR for LU non-financial (from reference data if seeded, else empty)
        assert result["competent_authority"] in ("ILR", "")

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::AssessmentAuthorityTest -v`
Expected: FAIL — `entity_type_obj` parameter not accepted

- [ ] **Step 3: Modify assessment.py**

In `entity/assessment.py`, add `entity_type_obj=None` parameter to `run_entity_assessment()`:

Change the function signature (line 14) to:

```python
def run_entity_assessment(
    description: str,
    sector: str,
    entity_type: str,
    ms_established: str = "EU",
    ms_affected: list[str] | None = None,
    service_impact: str = "none",
    data_impact: str = "none",
    financial_impact: str = "none",
    safety_impact: str = "none",
    affected_persons_count: int = 0,
    suspected_malicious: bool = False,
    impact_duration_hours: int = 0,
    sector_specific: dict | None = None,
    entity_type_obj=None,
) -> dict:
```

Replace lines 135-148 (framework/authority determination + return) with:

```python
    # Determine framework and competent authority
    framework = _determine_framework(ms_established, sector, entity_type)

    # Read authority from EntityType FK if available, else fallback
    if entity_type_obj and entity_type_obj.competent_authority:
        competent_authority = entity_type_obj.competent_authority.abbreviation
    else:
        competent_authority = _determine_competent_authority(ms_established, sector)

    if entity_type_obj and entity_type_obj.csirt:
        csirt_abbrev = entity_type_obj.csirt.abbreviation
    else:
        csirt_abbrev = ""

    # Determine notification recipient
    notification_recipient = ""
    if entity_type_obj:
        ca_obj = entity_type_obj.competent_authority
        csirt_obj = entity_type_obj.csirt
        if ca_obj and ca_obj.receives_notifications:
            notification_recipient = ca_obj.abbreviation
        elif csirt_obj and csirt_obj.receives_notifications:
            notification_recipient = csirt_obj.abbreviation

    authority_override = entity_type_obj and not entity_type_obj.ca_auto_assigned if entity_type_obj else False

    return {
        "sector": sector,
        "entity_type": entity_type,
        "ms_established": ms_established,
        "cross_border": cross_border,
        "significance": significance,
        "significant_incident": significant_incident,
        "model": model_used,
        "framework": framework,
        "competent_authority": competent_authority,
        "csirt": csirt_abbrev,
        "notification_recipient": notification_recipient,
        "authority_override": authority_override,
        "early_warning": early_warning.to_dict(),
    }
```

Keep `_determine_competent_authority()` as a fallback for when `entity_type_obj` is None (e.g., core library tests that don't use Django models).

- [ ] **Step 4: Update run_multi_entity_assessment to pass entity_type_obj**

In `run_multi_entity_assessment()`, update the `per_type_results.append(...)` block (line 269-286) to include the new fields:

```python
        per_type_results.append({
            "sector": impact["sector"],
            "entity_type": impact["entity_type"],
            "ms_affected": ms_affected,
            "service_impact": impact.get("service_impact", "none"),
            "data_impact": impact.get("data_impact", "none"),
            "safety_impact": impact.get("safety_impact", "none"),
            "financial_impact": impact.get("financial_impact", "none"),
            "affected_persons_count": impact.get("affected_persons_count", 0),
            "impact_duration_hours": impact.get("impact_duration_hours", 0),
            "significant_incident": sig_bool,
            "significance_label": sig_label,
            "model": result.get("model", ""),
            "triggered_criteria": sig_data.get("triggered_criteria", []),
            "framework": result.get("framework", ""),
            "competent_authority": result.get("competent_authority", ""),
            "csirt": result.get("csirt", ""),
            "notification_recipient": result.get("notification_recipient", ""),
            "authority_override": result.get("authority_override", False),
            "early_warning": result.get("early_warning", {}),
        })
```

- [ ] **Step 5: Update views.py to pass entity_type_obj**

In `entity/views.py`, in `assessment_form_view`, update the `run_multi_entity_assessment` call area. The `run_entity_assessment` is called inside `run_multi_entity_assessment`, which doesn't currently pass `entity_type_obj`. We need to add EntityType lookup in `run_multi_entity_assessment`. 

Add `entity_type_objs=None` parameter to `run_multi_entity_assessment()`:

```python
def run_multi_entity_assessment(
    description: str,
    per_type_impacts: list[dict],
    ms_established: str = "EU",
    suspected_malicious: bool = False,
    entity_type_objs: dict | None = None,
) -> dict:
```

In the loop (line 239-255), pass the entity_type_obj:

```python
    for impact in per_type_impacts:
        ms_affected = impact.get("ms_affected") or []
        et_key = f"{impact['sector']}:{impact['entity_type']}"
        et_obj = entity_type_objs.get(et_key) if entity_type_objs else None
        result = run_entity_assessment(
            ...
            entity_type_obj=et_obj,
        )
```

In `entity/views.py`, in `assessment_form_view`, build the `entity_type_objs` dict before calling `run_multi_entity_assessment`:

```python
                # Build EntityType object lookup
                et_objs = {}
                for et in entity.entity_types.all():
                    et_objs[f"{et.sector}:{et.entity_type}"] = et

                multi_result = run_multi_entity_assessment(
                    description=fields["description"],
                    per_type_impacts=per_type_impacts,
                    ms_established=entity.ms_established,
                    suspected_malicious=fields["suspected_malicious"],
                    entity_type_objs=et_objs,
                )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py entity/tests/test_assessment.py -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add entity/assessment.py entity/views.py entity/tests/test_authorities.py
git commit -m "feat: assessment engine reads authority from EntityType FK"
```

---

### Task 5: Admin Interface Enhancements

**Files:**
- Modify: `entity/admin.py`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::AdminAuthorityTest -v`
Expected: FAIL — admin not registered for new models

- [ ] **Step 3: Update admin.py**

Add to `entity/admin.py` imports (line 10):

```python
from .models import Assessment, CompetentAuthority, CSIRT, Entity, EntityType, Submission
```

Add after the import block:

```python
@admin.register(CompetentAuthority)
class CompetentAuthorityAdmin(admin.ModelAdmin):
    list_display = ("abbreviation", "name", "ms", "receives_notifications")
    list_filter = ("ms", "receives_notifications")
    search_fields = ("name", "abbreviation")


@admin.register(CSIRT)
class CSIRTAdmin(admin.ModelAdmin):
    list_display = ("abbreviation", "name", "ms", "receives_notifications", "emergency_phone")
    list_filter = ("ms", "receives_notifications")
    search_fields = ("name", "abbreviation")
```

Update `EntityTypeInline` to show authority columns:

```python
class EntityTypeInline(admin.TabularInline):
    model = EntityType
    fields = ("sector", "entity_type", "competent_authority", "csirt", "ca_auto_assigned", "added_at")
    readonly_fields = ("added_at",)
    extra = 1
```

Update `EntityTypeAdmin`:

```python
@admin.register(EntityType)
class EntityTypeAdmin(admin.ModelAdmin):
    list_display = ("entity", "sector", "entity_type", "competent_authority", "csirt", "ca_auto_assigned", "added_at")
    list_filter = ("sector", "competent_authority", "csirt")
    search_fields = ("entity__organisation_name", "entity_type")
    actions = ["reassign_authority"]

    @admin.action(description="Re-assign authority automatically")
    def reassign_authority(self, request, queryset):
        from .authority import assign_authority
        count = 0
        for et in queryset:
            et.ca_auto_assigned = True
            et.csirt_auto_assigned = True
            et.save(update_fields=["ca_auto_assigned", "csirt_auto_assigned"])
            assign_authority(et)
            count += 1
        messages.success(request, f"Re-assigned authority for {count} entity type(s).")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add entity/admin.py entity/tests/test_authorities.py
git commit -m "feat: admin interface for CompetentAuthority, CSIRT, and EntityType authority display"
```

---

### Task 6: MISP Export + Template Update

**Files:**
- Modify: `entity/misp_export.py`
- Modify: `data/misp-objects/cyberscale-entity-assessment/definition.json`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
from entity.models import Assessment


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::MISPExportAuthorityTest -v`
Expected: FAIL — `csirt` attribute not in export

- [ ] **Step 3: Update misp_export.py**

In `entity/misp_export.py`, in the `build_misp_event_global` function's per-type attribute list (the `attrs = [...]` block), add after the `competent-authority` attribute:

```python
            _attr("csirt", "text", r.get("csirt", "")),
            _attr("notification-recipient", "text", r.get("notification_recipient", "")),
```

Apply the same addition to `build_misp_event` and `build_misp_event_for_type` functions.

- [ ] **Step 4: Update MISP object template**

In `data/misp-objects/cyberscale-entity-assessment/definition.json`, add to the `"attributes"` object and bump version:

Change `"version": 1` to `"version": 2`.

Add after the `"competent-authority"` entry:

```json
    "csirt": {"misp-attribute": "text", "ui-priority": 16, "description": "Assigned CSIRT abbreviation"},
    "notification-recipient": {"misp-attribute": "text", "ui-priority": 17, "description": "Who receives Art. 23 notifications"},
```

Shift the `ui-priority` of `framework`, `early-warning-recommended`, `early-warning-deadline`, `triggered-criteria` up by 2.

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::MISPExportAuthorityTest -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add entity/misp_export.py data/misp-objects/cyberscale-entity-assessment/definition.json entity/tests/test_authorities.py
git commit -m "feat: add csirt and notification-recipient to MISP assessment export"
```

---

### Task 7: UI Updates — Dashboard + Result Page

**Files:**
- Modify: `templates/entity/partials/entity_types.html`
- Modify: `templates/entity/assessment_result.html`
- Test: `entity/tests/test_authorities.py` (append)

- [ ] **Step 1: Write failing tests**

Append to `entity/tests/test_authorities.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py::UIAuthorityTest -v`
Expected: FAIL for dashboard (ILR/CIRCL not shown in entity types partial)

- [ ] **Step 3: Update entity_types.html partial**

Replace `templates/entity/partials/entity_types.html`:

```html
<ul style="list-style: none; padding: 0; margin: 0;">
  {% for et in entity_types %}
  <li style="display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0;">
    <span>{{ et.sector_label }} / {{ et.label }}</span>
    {% if et.competent_authority %}
      <small style="color: var(--cs-text-muted);">CA: {{ et.competent_authority.abbreviation }}</small>
    {% endif %}
    {% if et.csirt %}
      <small style="color: var(--cs-text-muted);">CSIRT: {{ et.csirt.abbreviation }}</small>
    {% endif %}
    {% if entity_types|length > 1 %}
    <form method="post" action="{% url 'remove_entity_type' et.pk %}" style="display:inline;"
          hx-post="{% url 'remove_entity_type' et.pk %}"
          hx-target="#entity-types-list"
          hx-swap="innerHTML">
      {% csrf_token %}
      <button type="submit" style="background:none;border:none;color:var(--cs-significant);cursor:pointer;padding:0;font-size:0.8rem;" onclick="return confirm('Remove this entity type?')">x</button>
    </form>
    {% endif %}
  </li>
  {% endfor %}
</ul>
```

- [ ] **Step 4: Update assessment_result.html**

In `templates/entity/assessment_result.html`, in each per-type result card, after the `competent_authority` line (line 41), add:

```html
      {% if r.csirt %}<p><strong>CSIRT:</strong> {{ r.csirt }}</p>{% endif %}
      {% if r.notification_recipient %}<p><strong>Notify:</strong> {{ r.notification_recipient }}</p>{% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/test_authorities.py -v`
Expected: ALL PASS

- [ ] **Step 6: Run full test suite**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v --ignore=entity/tests/test_misp_integration.py`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add templates/entity/partials/entity_types.html templates/entity/assessment_result.html entity/tests/test_authorities.py
git commit -m "feat: show authority and CSIRT assignments in dashboard and result page"
```

---

### Task 8: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full web test suite**

Run: `docker compose exec cyberscale-web python -m pytest entity/tests/ -v --ignore=entity/tests/test_misp_integration.py`
Expected: ALL PASS

- [ ] **Step 2: Run core library tests**

Run: `docker compose exec cyberscale-web python -m pytest src/tests/ -v --ignore=src/tests/test_cwe_enrichment.py --ignore=src/tests/test_generation_balance.py --ignore=src/tests/test_mix_curated.py --ignore=src/tests/test_weighted_loss.py`
Expected: ALL PASS (assessment.py changes are backward-compatible via `entity_type_obj=None` default)

- [ ] **Step 3: Manual smoke test**

1. Register a new entity (energy/LU) — verify EntityType gets ILR + CIRCL auto-assigned
2. Add a banking entity type — verify it gets CSSF + CIRCL
3. Run an assessment — verify result shows ILR, CIRCL, notification recipient
4. Check Django admin — CA and CSIRT lists populated, EntityType shows authority columns
5. Admin override: change an EntityType's CA to CSSF — verify `ca_auto_assigned=False`
6. Admin action "Re-assign authority automatically" — verify it resets to ILR

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: smoke test adjustments for authority registry"
```
