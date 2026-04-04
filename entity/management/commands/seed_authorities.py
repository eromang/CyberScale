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
