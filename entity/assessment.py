"""Assessment engine integration for the Django web app.

Wraps the CyberScale core library's deterministic assessment (IR thresholds
+ national modules). Falls back gracefully when ML models are unavailable.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("cyberscale.web.assessment")


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
) -> dict:
    """Run the entity assessment using CyberScale core library.

    Three-tier routing (deterministic tiers first):
    1. IR thresholds (EU-wide, Arts. 5-14)
    2. National thresholds (LU ILR / BE CCB)
    3. NIS2 ML model (requires trained model — skipped if unavailable)

    Returns a result dict with significance, triggered criteria, early warning, etc.
    """
    from cyberscale.models.contextual_ir import is_ir_entity, assess_ir_significance
    from cyberscale.models.early_warning import recommend_early_warning
    from cyberscale.national.registry import get_national_module

    cross_border = bool(
        ms_affected and any(ms != ms_established for ms in ms_affected)
    )

    significance = None
    significant_incident = None
    model_used = None

    # Tier 1: IR thresholds
    if is_ir_entity(entity_type):
        ir_result = assess_ir_significance(
            entity_type=entity_type,
            service_impact=service_impact,
            data_impact=data_impact,
            financial_impact=financial_impact,
            safety_impact=safety_impact,
            affected_persons_count=affected_persons_count,
            suspected_malicious=suspected_malicious,
            impact_duration_hours=impact_duration_hours,
            cross_border=cross_border,
        )
        significance = ir_result.to_dict()
        significant_incident = ir_result.significant_incident
        model_used = "ir_thresholds"
        logger.info("Tier 1 IR: entity_type=%s significant=%s", entity_type, significant_incident)

    # Tier 2: National thresholds
    if significance is None:
        national = get_national_module(ms_established)
        if national is not None:
            is_covered_fn, assess_fn = national
            if is_covered_fn(sector, entity_type):
                nat_result = assess_fn(
                    sector=sector,
                    entity_type=entity_type,
                    service_impact=service_impact,
                    data_impact=data_impact,
                    affected_persons_count=affected_persons_count,
                    financial_impact=financial_impact,
                    safety_impact=safety_impact,
                    impact_duration_hours=impact_duration_hours,
                    cross_border=cross_border,
                    suspected_malicious=suspected_malicious,
                    sector_specific=sector_specific,
                )
                significance = nat_result.to_dict()
                significant_incident = nat_result.significant_incident
                model_used = f"national_{ms_established.lower()}"
                logger.info(
                    "Tier 2 national_%s: sector=%s significant=%s",
                    ms_established.lower(), sector, significant_incident,
                )

    # Tier 3: NIS2 ML model (try, but graceful fallback)
    if significance is None:
        try:
            from cyberscale.tools.entity_incident import _get_classifier, _assess_entity_incident
            clf = _get_classifier()
            if clf is not None:
                full_result = _assess_entity_incident(
                    clf, description, sector, entity_type,
                    ms_established=ms_established, ms_affected=ms_affected,
                    service_impact=service_impact, data_impact=data_impact,
                    financial_impact=financial_impact, safety_impact=safety_impact,
                    affected_persons_count=affected_persons_count,
                    suspected_malicious=suspected_malicious,
                    impact_duration_hours=impact_duration_hours,
                    sector_specific=sector_specific,
                )
                return full_result
        except Exception:
            logger.warning("ML model unavailable, using heuristic fallback")

        # Heuristic fallback when no ML model and no deterministic tier matched
        significance, significant_incident = _heuristic_significance(
            service_impact=service_impact,
            data_impact=data_impact,
            safety_impact=safety_impact,
            financial_impact=financial_impact,
            affected_persons_count=affected_persons_count,
            suspected_malicious=suspected_malicious,
            cross_border=cross_border,
        )
        model_used = "heuristic_fallback"
        logger.info("Tier 3 heuristic fallback: significant=%s", significant_incident)

    # Early warning
    early_warning = recommend_early_warning(
        significant_incident=significant_incident,
        suspected_malicious=suspected_malicious,
        cross_border=cross_border,
    )

    # Determine framework and competent authority
    framework = _determine_framework(ms_established, sector, entity_type)
    competent_authority = _determine_competent_authority(ms_established, sector)

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
        "early_warning": early_warning.to_dict(),
    }


def _heuristic_significance(
    service_impact: str,
    data_impact: str,
    safety_impact: str,
    financial_impact: str,
    affected_persons_count: int,
    suspected_malicious: bool,
    cross_border: bool,
) -> tuple[dict, bool]:
    """Simple heuristic when no deterministic tier matched and ML is unavailable."""
    triggered = []

    if service_impact in ("unavailable", "sustained"):
        triggered.append("Service unavailability or sustained impact")
    if data_impact in ("exfiltrated", "compromised", "systemic"):
        triggered.append("Data exfiltration, compromise, or systemic impact")
    if safety_impact in ("health_damage", "death"):
        triggered.append("Safety impact: health damage or death")
    if financial_impact == "severe":
        triggered.append("Severe financial impact")
    if affected_persons_count >= 10000:
        triggered.append(f"Affected persons count ({affected_persons_count:,}) exceeds threshold")
    if suspected_malicious:
        triggered.append("Suspected malicious activity")
    if cross_border:
        triggered.append("Cross-border impact")

    significant = len(triggered) > 0

    return {
        "significant_incident": significant,
        "triggered_criteria": triggered,
        "note": "Heuristic assessment — ML model not available. Consider deploying models for more accurate classification.",
    }, significant


def _determine_framework(ms_established: str, sector: str, entity_type: str) -> str:
    """Determine applicable notification framework."""
    if ms_established == "LU":
        if sector in ("banking", "financial_market"):
            return "DORA (CSSF)"
        return "NIS2 (ILR)"
    if ms_established == "BE":
        return "NIS2 (CCB)"
    return "NIS2"


def _determine_competent_authority(ms_established: str, sector: str) -> str:
    """Determine competent authority based on MS and sector."""
    if ms_established == "LU":
        if sector in ("banking", "financial_market"):
            return "CSSF"
        return "ILR"
    if ms_established == "BE":
        if sector in ("banking", "financial_market"):
            return "BNB"
        return "CCB"
    return "National competent authority"
