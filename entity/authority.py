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
