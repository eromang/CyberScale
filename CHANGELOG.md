# Changelog

## 1.0.0 (2026-04-03)

Initial product release. Extracted from research repository.

### Pipeline

- **Phase 1:** Vulnerability scoring — ModernBERT-base multi-task model (62.3% band accuracy)
- **Phase 2:** Contextual severity — ML model (81.5% macro F1) + deterministic threshold routing
- **Phase 3:** Authority classification — fully deterministic (T/O levels + Blueprint matrix)
- **Phase 3a:** National CSIRT classification (single MS)
- **Phase 3b:** EU-CyCLONe classification (multi-MS with Officer inputs)

### Entity significance (three-tier routing)

- **Tier 1:** IR quantitative thresholds (EU-wide, Arts. 5-14) — 11 entity types
- **Tier 2:** National thresholds — Luxembourg (ILR) and Belgium (CCB)
- **Tier 3:** NIS2 ML model (qualitative fallback)

### National modules

- **Luxembourg (LU):** Per-sector ILR thresholds (electricity POD matrices, rail, gas, health, air, drinking water, digital services), DORA routing for banking, 20/20 curated scenarios
- **Belgium (BE):** CCB horizontal thresholds (EUR 250K financial, 20% users/1h availability, malicious CIA, third-party damage), DORA carve-out, 10/10 curated scenarios

### HCPN crisis qualification

- National crisis qualification layer (Cadre national v1.0)
- Three cumulative criteria for incidents, four for threats
- Fast-track provision (malicious unauthorized access bypasses Criterion 2)
- Cooperation mode mapping (Crise vs Alerte/CERC)
- Undetermined criteria with consultation recommendation
- 15/15 curated scenarios, 5/5 real incidents concordant

### Validation

- 485 unit tests
- 10 real RETEX incidents (5 LU concordant, 5 international)
- Extensible validation framework (`add_real_incident.py`)
- End-to-end demo scripts for LU, BE, and HCPN

### Infrastructure

- Centralized config module (reference-loaded enums)
- Structured logging at routing and classification decision points
- Pluggable national module registry
- Authority feedback store for rule calibration
