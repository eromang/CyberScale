"""Tests for the assessment engine wrapper."""

from django.test import TestCase

from entity.assessment import run_entity_assessment, run_multi_entity_assessment


class RunEntityAssessmentTest(TestCase):
    def test_ir_entity_returns_significance(self):
        result = run_entity_assessment(
            description="SCADA compromise",
            sector="energy",
            entity_type="electricity_undertaking",
            ms_established="LU",
            service_impact="unavailable",
            suspected_malicious=True,
        )
        assert "significance" in result
        assert "early_warning" in result
        assert result["model"] is not None

    def test_national_lu_entity(self):
        result = run_entity_assessment(
            description="Network outage",
            sector="energy",
            entity_type="distribution_system_operator",
            ms_established="LU",
            service_impact="degraded",
            impact_duration_hours=2,
        )
        assert result["model"] in ("ir_thresholds", "national_lu")

    def test_heuristic_fallback(self):
        result = run_entity_assessment(
            description="Minor incident",
            sector="food",
            entity_type="food_producer",
            ms_established="FR",
            service_impact="none",
        )
        assert result["model"] in ("heuristic_fallback", "nis2_ml")


class RunMultiEntityAssessmentTest(TestCase):
    def test_single_type(self):
        result = run_multi_entity_assessment(
            description="SCADA compromise",
            per_type_impacts=[{
                "sector": "energy",
                "entity_type": "electricity_undertaking",
                "ms_affected": ["LU"],
                "service_impact": "unavailable",
                "data_impact": "none",
                "safety_impact": "none",
                "financial_impact": "none",
                "affected_persons_count": 0,
                "impact_duration_hours": 3,
                "sector_specific": {},
            }],
            ms_established="LU",
            suspected_malicious=True,
        )
        assert len(result["per_type_results"]) == 1
        assert result["overall_significance_label"] != ""

    def test_multi_type(self):
        result = run_multi_entity_assessment(
            description="Multi-sector attack",
            per_type_impacts=[
                {
                    "sector": "energy",
                    "entity_type": "electricity_undertaking",
                    "ms_affected": ["LU", "DE"],
                    "service_impact": "unavailable",
                    "data_impact": "compromised",
                    "safety_impact": "health_risk",
                    "financial_impact": "significant",
                    "affected_persons_count": 50000,
                    "impact_duration_hours": 4,
                    "sector_specific": {},
                },
                {
                    "sector": "drinking_water",
                    "entity_type": "drinking_water_supplier",
                    "ms_affected": ["LU"],
                    "service_impact": "degraded",
                    "data_impact": "none",
                    "safety_impact": "health_risk",
                    "financial_impact": "minor",
                    "affected_persons_count": 120000,
                    "impact_duration_hours": 8,
                    "sector_specific": {},
                },
            ],
            ms_established="LU",
            suspected_malicious=True,
        )
        assert len(result["per_type_results"]) == 2
        # Each result should have its own impact data
        assert result["per_type_results"][0]["service_impact"] == "unavailable"
        assert result["per_type_results"][1]["service_impact"] == "degraded"
        assert result["per_type_results"][0]["ms_affected"] == ["LU", "DE"]
        assert result["per_type_results"][1]["ms_affected"] == ["LU"]
        # Overall should be the most severe
        assert result["overall_significance_label"] in ("SIGNIFICANT", "LIKELY", "UNDETERMINED")

    def test_overall_picks_most_severe(self):
        result = run_multi_entity_assessment(
            description="Test",
            per_type_impacts=[
                {
                    "sector": "food",
                    "entity_type": "food_producer",
                    "ms_affected": [],
                    "service_impact": "none",
                    "data_impact": "none",
                    "safety_impact": "none",
                    "financial_impact": "none",
                    "affected_persons_count": 0,
                    "impact_duration_hours": 0,
                    "sector_specific": {},
                },
                {
                    "sector": "energy",
                    "entity_type": "electricity_undertaking",
                    "ms_affected": ["LU"],
                    "service_impact": "unavailable",
                    "data_impact": "none",
                    "safety_impact": "none",
                    "financial_impact": "none",
                    "affected_persons_count": 0,
                    "impact_duration_hours": 3,
                    "sector_specific": {},
                },
            ],
            ms_established="LU",
            suspected_malicious=True,
        )
        # The energy type should be more severe than food
        labels = [r["significance_label"] for r in result["per_type_results"]]
        assert result["overall_significance_label"] == max(
            labels,
            key=lambda l: {"SIGNIFICANT": 6, "LIKELY": 5, "UNDETERMINED": 4,
                           "UNCERTAIN": 3, "NOT SIGNIFICANT": 2, "UNLIKELY": 1, "": 0}.get(l, 0)
        )
