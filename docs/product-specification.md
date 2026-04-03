# CyberScale — Product Specification

**Version:** 1.0 draft
**Date:** 2026-04-03
**Status:** Design

---

## 1. Product Vision

CyberScale is a multi-phase cyber incident severity assessment platform that helps NIS2-regulated entities determine whether an incident is significant, which notification framework applies, and what action to take — then delivers structured assessment data to CSIRTs and competent authorities via MISP.

---

## 2. Target Users

| User group | Role in NIS2 | Primary need | Interface |
|---|---|---|---|
| **Entities** (essential + important) | Incident reporters (Art. 23) | "Is this significant? Should I notify?" | Web form |
| **CSIRTs** (national) | Incident receivers + classifiers | "What's the aggregated picture? What coordination?" | MISP + Python library + MCP |
| **Competent authorities** | Supervisors | "Are entities assessing correctly?" | MISP + Django admin |
| **CyCLONe representatives** | EU-level coordinators | "Is this large-scale? What coordination level?" | Python library + MCP |
| **Cyber crisis authorities** (HCPN, NCCN) | Crisis plan activation | "Does this trigger the national crisis plan?" | Python library + MCP |

---

## 3. Architecture

```
                          ┌─────────────────────────────┐
                          │     CyberScale Platform      │
                          │                               │
  Entity ──── Web UI ────►│  Django + HTMX                │
  (browser)   (forms)     │    │                          │
                          │    ├── Assessment engine       │
                          │    │   (CyberScale core lib)  │
                          │    │                          │
                          │    ├── PDF generation          │──► PDF report
                          │    │   (weasyprint)           │    (entity keeps)
                          │    │                          │
                          │    ├── MISP push               │──► CSIRT MISP instance
                          │    │   (PyMISP)               │    (authority consumes)
                          │    │                          │
                          │    ├── MISP JSON export        │──► Downloadable file
                          │    │                          │    (manual import)
                          │    │                          │
                          │    └── REST API                │──► Programmatic access
                          │                               │
  AI tool ── MCP server ─►│  FastMCP (separate process)   │
  (Claude,    (JSON-RPC)  │    └── CyberScale core lib    │
   Copilot)               │                               │
                          └─────────────────────────────┘
                                       │
                              ┌────────┴────────┐
                              │   PostgreSQL     │
                              │   (entity        │
                              │    profiles,     │
                              │    assessments,  │
                              │    history)      │
                              └─────────────────┘
```

### Components

| Component | Technology | Responsibility |
|---|---|---|
| **Web frontend** | Django templates + HTMX | Entity form, result display, conditional fields |
| **Backend** | Django 5.x | User auth, entity profiles, assessment history, REST API |
| **Assessment engine** | CyberScale Python library | Phase 1-3 + national modules + HCPN — unchanged from research |
| **PDF export** | weasyprint | HTML template → PDF report for entity records |
| **MISP integration** | PyMISP | Push structured events to authority MISP instances |
| **MCP server** | FastMCP | AI-assisted workflows (separate process, same core library) |
| **Database** | PostgreSQL | Entity profiles, assessments, submission history, MISP config |
| **Containerization** | Docker Compose | Local development + deployment |

---

## 4. Entity Workflow

### 4.1 Registration

Entity registers with:
- Organisation name
- NIS2 sector (dropdown, HTMX-filtered)
- Entity type (filtered by sector)
- Member state established
- Competent authority (auto-determined from sector + MS)
- Optional: MISP instance URL + API key (for direct push)

Post-registration, entities can add multiple entity types from their dashboard (e.g., electricity_undertaking + drinking_water_supplier). Entity types can be removed (minimum one required).

### 4.2 Incident Assessment

**Step 1 — Incident context** (global, incident-level)
- Free-text description
- Affected entity types (multi-select from registered types)
- Suspected malicious: yes / no
- Physical access breach: yes / no (IR entities only)

**Step 2 — Per-entity-type impact** (one fieldset per selected entity type, HTMX-rendered)

Each entity type gets its own:
- MS affected (multi-select — different types can have different geographic scope)
- Service impact: none / partial / degraded / unavailable / sustained
- Data impact: none / accessed / exfiltrated / compromised / systemic
- Safety impact: none / health_risk / health_damage / death
- Financial impact: none / minor / significant / severe
- Affected persons count
- Impact duration (hours)
- Sector-specific fields (inline, only shown for relevant sectors):
  - LU electricity: PODs affected, voltage level, SCADA unavailable minutes
  - LU rail: trains cancelled %, slots impacted
  - LU health: persons with health impact, analyses affected %

**Step 3 — Result** (per-entity-type + overall)
- Overall significance: most severe across all affected entity types
- Per-entity-type result cards:
  - Significance determination: SIGNIFICANT / NOT SIGNIFICANT / UNDETERMINED
  - Framework: NIS2 / DORA / ILR / CCB NIS2
  - Competent authority: ILR / CCB / CSSF / BNB
  - Triggered criteria (with explanations)
- Early warning: RECOMMENDED / NOT RECOMMENDED
  - Recommended if any entity type triggers it
  - Deadline (24h / 4h for DORA / 24h for BE trust services)
  - Required content for notification
- Next steps (actionable guidance)

### 4.3 Export and Submission

| Action | Output | Destination |
|---|---|---|
| **Download PDF** | Assessment report with per-type results + per-type impacts | Entity internal records |
| **Download MISP JSON** | Global MISP event (one object per entity type) | Manual import to authority MISP |
| **Download per-type MISP** | Single-type MISP event (when multiple types) | Sector-specific authority import |
| **Push to CSIRT** | MISP event via PyMISP API | Authority MISP instance |
| **Save draft** | Persisted in database | Resume later |
| **Delete draft** | Remove incomplete assessment | Dashboard action |

### 4.4 Assessment History

Entity can view past assessments, re-export PDF/MISP, track submission status. Draft assessments shown with DRAFT badge and resume/delete actions.

---

## 5. Authority Workflow

### 5.1 CSIRT (Phase 3a — National Classification)

**Input:** Multiple entity assessment MISP events from their constituency.

**Process:**
1. MISP events ingested (automatic or manual)
2. CyberScale aggregates entity data → Phase 3a
3. Deterministic T/O level derivation + Blueprint matrix
4. Cross-border detection → CSIRT Network sharing flag

**Output:** National classification event pushed back to MISP.

### 5.2 CyCLONe Representative (Phase 3b — EU Classification)

**Input:** National classifications from multiple MS (via MISP sync).

**Process:**
1. National classifications aggregated
2. CyCLONe Officer inputs (political sensitivity, capacity, coordination needs)
3. EU-level classification

**Output:** EU classification event.

### 5.3 Crisis Authority (HCPN)

**Input:** Impact data on Luxembourg + authority judgment inputs.

**Process:**
1. Three cumulative criteria evaluation (or four for threats)
2. Cooperation mode determination
3. Consultation recommendation for undetermined criteria

**Output:** Crisis qualification result.

---

## 6. Data Model

### 6.1 Django Models

```
Entity (Django User extension)
├── organisation_name
├── sector (legacy — primary sector)
├── entity_type (legacy — primary entity type)
├── ms_established
├── competent_authority (auto)
├── misp_instance_url (optional)
├── misp_api_key (encrypted, optional)
└── misp_default_tlp

EntityType (M2M — one Entity has many)
├── entity (FK → Entity)
├── sector
├── entity_type
└── added_at

Assessment
├── entity (FK → Entity)
├── created_at
├── status: draft / completed / submitted
├── description (text)
├── suspected_malicious (bool — global, incident-level)
├── physical_access_breach (bool — global)
├── affected_entity_types (JSON — list of {sector, entity_type})
├── per_type_impacts (JSON — per-type MS affected, impacts, sector_specific)
├── impact fields (service, data, safety, financial, persons, duration — backward compat, worst-case)
├── sector_specific (JSON — backward compat)
├── assessment_results (JSON — per-type significance results)
├── result_significance (bool | null — overall, most severe)
├── result_significance_label (text — overall)
├── result_model (text — primary type's model)
├── result_criteria (JSON — primary type's criteria)
├── result_framework (text — primary type's framework)
├── result_competent_authority (text)
├── result_early_warning (JSON — overall)
├── result_raw (JSON — full engine output)
├── misp_event_uuid (optional — set after export)
└── pdf_generated_at (optional)

Submission
├── assessment (FK → Assessment)
├── submitted_at
├── target: misp_push / pdf_download / misp_json_download
├── misp_event_id (optional)
└── status: pending / success / failed
```

### 6.2 MISP Event Structure

Each entity assessment produces one MISP event containing:

```json
{
  "info": "CyberScale entity assessment: energy / electricity_undertaking",
  "tags": [
    "cyberscale:phase=\"phase-2\"",
    "cyberscale:significance-model=\"national_lu_thresholds\"",
    "nis2:significance=\"significant\"",
    "tlp:amber"
  ],
  "objects": [
    {
      "name": "cyberscale-entity-assessment",
      "attributes": {
        "sector": "energy",
        "entity-type": "electricity_undertaking",
        "ms-established": "LU",
        "service-impact": "unavailable",
        "significant-incident": true,
        "triggered-criteria": "ILR/N22/4: HV/EHV transmission network incident",
        "competent-authority": "ILR",
        "early-warning-recommended": true,
        "early-warning-deadline": "24h"
      }
    }
  ]
}
```

---

## 7. PDF Report Structure

```
┌─────────────────────────────────────────┐
│  CYBERSCALE — Incident Assessment       │
│  [Date] [Assessment ID]                 │
├─────────────────────────────────────────┤
│  Entity: [Organisation name]            │
│  Sector: [sector] / Entity type: [type] │
│  MS established: [MS]                   │
├─────────────────────────────────────────┤
│  SIGNIFICANCE: ██ SIGNIFICANT ██        │
│  Framework: NIS2 (ILR)                  │
│  Competent authority: ILR               │
├─────────────────────────────────────────┤
│  Triggered criteria:                    │
│  • ILR/N22/4: HV/EHV transmission       │
│  • ILR/N22/4: SCADA system impact        │
│  • Common: safety/security risk           │
├─────────────────────────────────────────┤
│  EARLY WARNING: RECOMMENDED             │
│  Deadline: 24 hours from awareness      │
│  Required content:                      │
│  • Whether suspected malicious          │
│  • Whether cross-border impact          │
├─────────────────────────────────────────┤
│  Impact summary:                        │
│  Service: unavailable (3.5h)            │
│  Data: none                             │
│  Safety: death                          │
│  Financial: severe                      │
├─────────────────────────────────────────┤
│  Next steps:                            │
│  1. Submit early warning to ILR         │
│  2. Prepare 72h incident notification   │
│  3. Final report due within 1 month     │
├─────────────────────────────────────────┤
│  Generated by CyberScale v1.0.0        │
│  Assessment is advisory — notification  │
│  decision remains the entity's          │
│  responsibility.                        │
└─────────────────────────────────────────┘
```

---

## 8. Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Python | ≥3.11 |
| Web framework | Django | 5.x |
| Frontend interactivity | HTMX | 2.x |
| CSS | Tailwind CSS or Pico CSS | — |
| PDF generation | weasyprint | ≥62 |
| MISP integration | PyMISP | ≥2.4 |
| Database | PostgreSQL | 16 |
| Assessment engine | CyberScale core library | 1.0.0 |
| MCP server | FastMCP | ≥3.1 |
| ML inference | PyTorch + Transformers | ≥2.2 / ≥4.40 |
| Containerization | Docker Compose | — |

---

## 9. Security Considerations

| Concern | Approach |
|---|---|
| Entity MISP API keys | Encrypted at rest (Django Fernet or similar) |
| Assessment data | Entity can only see their own assessments |
| TLP marking | Configurable per entity; default TLP:AMBER |
| Authentication | Django auth with session-based login; optional SSO integration |
| HTTPS | Required in production (TLS termination at reverse proxy) |
| Assessment disclaimer | "Advisory — notification decision remains the entity's responsibility" |
| Data sovereignty | Self-hosted — entity/authority controls where data resides |

---

## 10. Deployment Options

| Option | For | Stack |
|---|---|---|
| **Docker Compose (local)** | Development, playground, training | Django + PostgreSQL + (optional MISP) |
| **Single server** | Small CSIRT, single entity | Docker Compose on VPS/bare metal |
| **Production** | National deployment | Django behind Nginx/Gunicorn, PostgreSQL, MISP instance(s) |

---

## 11. Roadmap

| Version | Scope |
|---|---|
| **v1.0** | Entity web form (multi-entity-type, per-type impacts) + PDF + MISP export + MISP push + save draft + Django admin + Docker playground |
| **v1.1** | REST API (programmatic assessment access) |
| **v1.2** | Authority & CSIRT registry — CompetentAuthority + CSIRT models, entity type → authority assignment (sector+MS), notification routing per MS national implementation (Art. 23), MISP-A push routing per authority, reference data seeding |
| **v1.3** | Notification form generation (Art. 23 structured output — early warning, incident notification, final report) |
| **v1.4** | MISP-A ↔ MISP-B sync — authority-side MISP receives entity profiles + assessments via MISP sync, phase 2 assessment consumed from MISP-B |
| **v1.5** | Additional national modules (as regulatory data becomes available) |
| **v2.0** | Authority portal (CyberScale Authority) — CSIRT/CA-facing web interface connected to MISP-B, phase 2 contextual severity on authority side, cross-entity correlation, API for programmatic access |
| **v2.1** | Temporal incident tracking (early warning → notification → final report timeline per Art. 23(4)) |
| **v2.2** | CSIRT dashboard (active incidents, sector aggregation, cross-border impact view) |
| **v2.3** | Exercise support (scenario injection, timed escalation for BlueOLEx/CyberEurope) |

### Architecture

```
Entity Side (operated by CA/CSIRT)       Authority/CSIRT Side
──────────────────────────────────       ────────────────────
cyberscale-web ──push──► MISP-A  ──sync──►  MISP-B ◄── authority-web (v2.0)
(entity portal)          (entity MISP)      (authority MISP)
                                                │
Art. 27 profiles                         Phase 2 assessment
Art. 23 notifications                    Cross-entity correlation
Self-assessment (phase 1)                CSIRT dashboard (v2.2)
PDF/MISP JSON export                     API access (v2.0)
```

cyberscale-web is the entity-facing portal, managed by the competent authority or CSIRT. MISP-A stores entity profiles and assessment events. MISP-B on the authority side syncs from MISP-A and serves as the backend for authority workflows, phase 2 assessment, and API capabilities.
