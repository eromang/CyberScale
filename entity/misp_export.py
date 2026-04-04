"""MISP JSON export for CyberScale assessments."""

from __future__ import annotations

import uuid
from datetime import datetime


def build_misp_event(assessment, entity, profile_event_uuid: str = "") -> dict:
    """Build a MISP event dict from an Assessment + Entity.

    Follows the cyberscale-entity-assessment object structure
    from product spec section 6.2.
    """
    event_uuid = assessment.misp_event_uuid or str(uuid.uuid4())

    # Map significance to MISP threat level
    sig_label = assessment.result_significance_label
    if sig_label in ("SIGNIFICANT", "LIKELY"):
        threat_level_id = "1"  # High
        sig_tag = "significant"
    elif sig_label in ("NOT SIGNIFICANT", "UNLIKELY"):
        threat_level_id = "3"  # Low
        sig_tag = "not-significant"
    else:
        threat_level_id = "2"  # Medium
        sig_tag = "undetermined"

    # Build attributes list
    attributes = [
        _attr("sector", "text", assessment.sector),
        _attr("entity-type", "text", assessment.entity_type),
        _attr("ms-established", "text", entity.ms_established),
        _attr("description", "text", assessment.description),
        _attr("service-impact", "text", assessment.service_impact),
        _attr("data-impact", "text", assessment.data_impact),
        _attr("safety-impact", "text", assessment.safety_impact),
        _attr("financial-impact", "text", assessment.financial_impact),
        _attr("affected-persons-count", "counter", str(assessment.affected_persons_count)),
        _attr("impact-duration-hours", "counter", str(assessment.impact_duration_hours)),
        _attr("suspected-malicious", "boolean", "1" if assessment.suspected_malicious else "0"),
        _attr("significant-incident", "boolean", "1" if assessment.result_significance else "0"),
        _attr("significance-model", "text", assessment.result_model),
        _attr("competent-authority", "text", assessment.result_competent_authority),
        _attr("csirt", "text", ""),
        _attr("notification-recipient", "text", ""),
        _attr("framework", "text", assessment.result_framework),
        _attr("early-warning-recommended", "boolean",
              "1" if assessment.result_early_warning.get("recommended") else "0"),
        _attr("early-warning-deadline", "text",
              assessment.result_early_warning.get("deadline", "")),
    ]

    # Triggered criteria as pipe-separated text
    criteria = assessment.result_criteria
    if criteria:
        _criteria_text = " | ".join(criteria) if isinstance(criteria, list) else str(criteria)
        attributes.append(_attr("triggered-criteria", "text", _criteria_text))

    tlp = entity.misp_default_tlp or "tlp:amber"

    obj_dict = {
        "name": "cyberscale-entity-assessment",
        "meta-category": "misc",
        "template_uuid": "c5e0f001-e27a-4f00-a000-000000000002",
        "template_version": "1",
        "uuid": str(uuid.uuid4()),
        "Attribute": attributes,
    }
    if profile_event_uuid:
        obj_dict["ObjectReference"] = [{
            "referenced_uuid": profile_event_uuid,
            "relationship_type": "belongs-to",
            "comment": "Entity profile for this assessment",
        }]

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {assessment.sector} / {assessment.entity_type}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "3",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:phase="phase-2"'},
                {"name": f'cyberscale:significance-model="{assessment.result_model}"'},
                {"name": f'nis2:significance="{sig_tag}"'},
                {"name": tlp},
            ],
            "Object": [obj_dict],
        }
    }


def build_misp_event_for_type(assessment, entity, type_result: dict, profile_event_uuid: str = "") -> dict:
    """Build a MISP event for a specific entity type result."""
    event_uuid = str(uuid.uuid4())

    sig_label = type_result.get("significance_label", "")
    if sig_label in ("SIGNIFICANT", "LIKELY"):
        threat_level_id = "1"
        sig_tag = "significant"
    elif sig_label in ("NOT SIGNIFICANT", "UNLIKELY"):
        threat_level_id = "3"
        sig_tag = "not-significant"
    else:
        threat_level_id = "2"
        sig_tag = "undetermined"

    ew = type_result.get("early_warning", {})
    criteria = type_result.get("triggered_criteria", [])
    criteria_text = " | ".join(criteria) if isinstance(criteria, list) and criteria else ""

    attributes = [
        _attr("sector", "text", type_result.get("sector", "")),
        _attr("entity-type", "text", type_result.get("entity_type", "")),
        _attr("ms-established", "text", entity.ms_established),
        _attr("ms-affected", "text", ", ".join(type_result.get("ms_affected", []))),
        _attr("description", "text", assessment.description),
        _attr("service-impact", "text", type_result.get("service_impact", assessment.service_impact)),
        _attr("data-impact", "text", type_result.get("data_impact", assessment.data_impact)),
        _attr("safety-impact", "text", type_result.get("safety_impact", assessment.safety_impact)),
        _attr("financial-impact", "text", type_result.get("financial_impact", assessment.financial_impact)),
        _attr("affected-persons-count", "counter", str(type_result.get("affected_persons_count", assessment.affected_persons_count))),
        _attr("impact-duration-hours", "counter", str(type_result.get("impact_duration_hours", assessment.impact_duration_hours))),
        _attr("suspected-malicious", "boolean", "1" if assessment.suspected_malicious else "0"),
        _attr("significant-incident", "boolean", "1" if type_result.get("significant_incident") else "0"),
        _attr("significance-model", "text", type_result.get("model", "")),
        _attr("competent-authority", "text", type_result.get("competent_authority", "")),
        _attr("csirt", "text", type_result.get("csirt", "")),
        _attr("notification-recipient", "text", type_result.get("notification_recipient", "")),
        _attr("framework", "text", type_result.get("framework", "")),
        _attr("early-warning-recommended", "boolean", "1" if ew.get("recommended") else "0"),
        _attr("early-warning-deadline", "text", ew.get("deadline", "")),
    ]
    if criteria_text:
        attributes.append(_attr("triggered-criteria", "text", criteria_text))

    tlp = entity.misp_default_tlp or "tlp:amber"

    obj_dict = {
        "name": "cyberscale-entity-assessment",
        "meta-category": "misc",
        "template_uuid": "c5e0f001-e27a-4f00-a000-000000000002",
        "template_version": "1",
        "uuid": str(uuid.uuid4()),
        "Attribute": attributes,
    }
    if profile_event_uuid:
        obj_dict["ObjectReference"] = [{
            "referenced_uuid": profile_event_uuid,
            "relationship_type": "belongs-to",
            "comment": "Entity profile for this assessment",
        }]

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {type_result.get('sector', '')} / {type_result.get('entity_type', '')}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "3",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:phase="phase-2"'},
                {"name": f'cyberscale:significance-model="{type_result.get("model", "")}"'},
                {"name": f'nis2:significance="{sig_tag}"'},
                {"name": tlp},
            ],
            "Object": [obj_dict],
        }
    }


def build_misp_event_global(assessment, entity, profile_event_uuid: str = "") -> dict:
    """Build a single MISP event with one object per affected entity type.

    One event = one incident. Multiple objects = multiple affected entity types.
    Uses overall significance for the event-level threat level.
    """
    event_uuid = assessment.misp_event_uuid or str(uuid.uuid4())

    sig_label = assessment.result_significance_label
    if sig_label in ("SIGNIFICANT", "LIKELY"):
        threat_level_id = "1"
        sig_tag = "significant"
    elif sig_label in ("NOT SIGNIFICANT", "UNLIKELY"):
        threat_level_id = "3"
        sig_tag = "not-significant"
    else:
        threat_level_id = "2"
        sig_tag = "undetermined"

    tlp = entity.misp_default_tlp or "tlp:amber"

    # Build one object per entity type result
    objects = []
    for r in (assessment.assessment_results or []):
        ew = r.get("early_warning", {})
        criteria = r.get("triggered_criteria", [])
        criteria_text = " | ".join(criteria) if isinstance(criteria, list) and criteria else ""

        attrs = [
            _attr("sector", "text", r.get("sector", "")),
            _attr("entity-type", "text", r.get("entity_type", "")),
            _attr("ms-established", "text", entity.ms_established),
            _attr("ms-affected", "text", ", ".join(r.get("ms_affected", []))),
            _attr("description", "text", assessment.description),
            _attr("service-impact", "text", r.get("service_impact", assessment.service_impact)),
            _attr("data-impact", "text", r.get("data_impact", assessment.data_impact)),
            _attr("safety-impact", "text", r.get("safety_impact", assessment.safety_impact)),
            _attr("financial-impact", "text", r.get("financial_impact", assessment.financial_impact)),
            _attr("affected-persons-count", "counter", str(r.get("affected_persons_count", assessment.affected_persons_count))),
            _attr("impact-duration-hours", "counter", str(r.get("impact_duration_hours", assessment.impact_duration_hours))),
            _attr("suspected-malicious", "boolean", "1" if assessment.suspected_malicious else "0"),
            _attr("significant-incident", "boolean", "1" if r.get("significant_incident") else "0"),
            _attr("significance-model", "text", r.get("model", "")),
            _attr("competent-authority", "text", r.get("competent_authority", "")),
            _attr("csirt", "text", r.get("csirt", "")),
            _attr("notification-recipient", "text", r.get("notification_recipient", "")),
            _attr("framework", "text", r.get("framework", "")),
            _attr("early-warning-recommended", "boolean", "1" if ew.get("recommended") else "0"),
            _attr("early-warning-deadline", "text", ew.get("deadline", "")),
        ]
        if criteria_text:
            attrs.append(_attr("triggered-criteria", "text", criteria_text))

        obj_dict = {
            "name": "cyberscale-entity-assessment",
            "meta-category": "misc",
            "template_uuid": "c5e0f001-e27a-4f00-a000-000000000002",
            "template_version": "1",
            "uuid": str(uuid.uuid4()),
            "Attribute": attrs,
        }
        if profile_event_uuid:
            obj_dict["ObjectReference"] = [{
                "referenced_uuid": profile_event_uuid,
                "relationship_type": "belongs-to",
                "comment": "Entity profile for this assessment",
            }]
        objects.append(obj_dict)

    # Fallback: if no assessment_results, use legacy single-object
    if not objects:
        return build_misp_event(assessment, entity, profile_event_uuid=profile_event_uuid)

    # Build sector list for event info
    sectors = [r.get("sector", "") for r in assessment.assessment_results]
    info_sectors = " + ".join(dict.fromkeys(s.replace("_", " ") for s in sectors))

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {info_sectors}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "3",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:phase="phase-2"'},
                {"name": f'nis2:significance="{sig_tag}"'},
                {"name": tlp},
            ],
            "Object": objects,
        }
    }


def _attr(relation: str, attr_type: str, value: str) -> dict:
    return {
        "object_relation": relation,
        "type": attr_type,
        "value": value,
    }
