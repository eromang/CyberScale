"""MISP JSON export for CyberScale assessments."""

from __future__ import annotations

import uuid
from datetime import datetime


def build_misp_event(assessment, entity) -> dict:
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

    return {
        "Event": {
            "info": f"CyberScale entity assessment: {assessment.sector} / {assessment.entity_type}",
            "date": assessment.created_at.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level_id,
            "analysis": "2",
            "distribution": "1",
            "uuid": event_uuid,
            "Tag": [
                {"name": 'cyberscale:phase="phase-2"'},
                {"name": f'cyberscale:significance-model="{assessment.result_model}"'},
                {"name": f'nis2:significance="{sig_tag}"'},
                {"name": tlp},
            ],
            "Object": [
                {
                    "name": "cyberscale-entity-assessment",
                    "meta-category": "misc",
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
