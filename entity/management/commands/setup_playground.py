"""Set up the CyberScale playground: superuser, entity, MISP connectivity check."""

import os

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from entity.models import Entity, EntityType


class Command(BaseCommand):
    help = "Set up the CyberScale playground (superuser + entity + MISP check)"

    def handle(self, *args, **options):
        self._create_superuser()
        self._check_misp()

    def _create_superuser(self):
        if User.objects.filter(is_superuser=True).exists():
            admin = User.objects.filter(is_superuser=True).first()
            self.stdout.write(f"Superuser already exists: {admin.username}")
        else:
            admin = User.objects.create_superuser("admin", "admin@cyberscale.local", "admin")
            self.stdout.write(self.style.SUCCESS("Created superuser: admin / admin"))

        if not Entity.objects.filter(user=admin).exists():
            entity = Entity.objects.create(
                user=admin,
                organisation_name="CyberScale Admin",
                sector="digital_infrastructure",
                entity_type="top_level_domain_name_registry",
                ms_established="LU",
            )
            EntityType.objects.create(
                entity=entity,
                sector="digital_infrastructure",
                entity_type="top_level_domain_name_registry",
            )
            self.stdout.write(self.style.SUCCESS("Created admin entity: CyberScale Admin"))
        else:
            self.stdout.write("Admin entity already exists.")

    def _check_misp(self):
        misp_url = os.environ.get("MISP_URL", "")
        misp_key = os.environ.get("MISP_API_KEY", "")
        ssl_verify = os.environ.get("MISP_SSL_VERIFY", "").lower() not in ("0", "false", "no", "")

        if not misp_url or not misp_key or misp_key == "changeme-run-misp-authkey-setup":
            self.stdout.write(self.style.WARNING(
                "MISP not configured. Run 'docker compose exec misp /scripts/misp-init.sh' first, "
                "then set MISP_API_KEY in docker-compose.yml."
            ))
            return

        try:
            import warnings
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            from pymisp import PyMISP
            misp = PyMISP(misp_url, misp_key, ssl=ssl_verify, timeout=15)
            user = misp.get_user("me")
            if isinstance(user, dict) and "User" in user:
                self.stdout.write(self.style.SUCCESS(
                    f"MISP connected: {user['User']['email']} at {misp_url}"
                ))
            else:
                self.stdout.write(self.style.ERROR(f"MISP auth failed: {user}"))
        except Exception as exc:
            msg = str(exc)
            if "500" in msg:
                # MISP may still be initializing — not a fatal error
                self.stdout.write(self.style.WARNING(
                    f"MISP reachable but still initializing ({misp_url}). Retry in a moment."
                ))
            else:
                self.stdout.write(self.style.ERROR(f"MISP connection failed: {exc}"))
