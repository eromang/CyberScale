"""MISP JSON export for CyberScale entity profiles (Art. 27)."""

from __future__ import annotations

import uuid


def build_misp_profile_event(entity) -> dict:
    """Build a MISP event dict for an entity profile.

    Creates a standalone event with a single cyberscale-entity-profile object
    containing all Art. 27 registration fields.
    """
    event_uuid = entity.misp_profile_event_uuid or str(uuid.uuid4())
    tlp = entity.misp_default_tlp or "tlp:amber"

    attributes = [
        _attr("organisation-name", "text", entity.organisation_name),
        _attr("address", "text", entity.address),
        _attr("contact-email", "email-src", entity.contact_email),
        _attr("contact-phone", "phone-number", entity.contact_phone),
        _attr("responsible-person-name", "text", entity.responsible_person_name),
        _attr("responsible-person-email", "email-src", entity.responsible_person_email),
        _attr("technical-contact-name", "text", entity.technical_contact_name),
        _attr("technical-contact-email", "email-src", entity.technical_contact_email),
        _attr("technical-contact-phone", "phone-number", entity.technical_contact_phone),
        _attr("ms-established", "text", entity.ms_established),
        _attr("ms-services", "text", ", ".join(entity.ms_services or [])),
    ]

    for cidr in (entity.ip_ranges or []):
        attributes.append(_attr("ip-range", "ip-src", cidr))

    for et in entity.entity_types.all():
        attributes.append(_attr("sector", "text", et.sector))
        attributes.append(_attr("entity-type", "text", et.entity_type))

    return {
        "Event": {
            "info": f"CyberScale entity profile: {entity.organisation_name}",
            "threat_level_id": "4",
            "analysis": "2",
            "distribution": "1",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:type="entity-profile"'},
                {"name": tlp},
            ],
            "Object": [
                {
                    "name": "cyberscale-entity-profile",
                    "meta-category": "misc",
                    "template_uuid": "c5e0f001-e27a-4f00-a000-000000000001",
                    "template_version": "1",
                    "uuid": str(uuid.uuid4()),
                    "Attribute": attributes,
                }
            ],
        }
    }


def _attr(relation: str, attr_type: str, value: str) -> dict:
    return {
        "object_relation": relation,
        "type": attr_type,
        "value": value,
    }
