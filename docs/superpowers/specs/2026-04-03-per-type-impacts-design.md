# Per-Entity-Type Impact Assessment — Design Spec

**Date:** 2026-04-03
**Status:** Approved
**Scope:** Restructure assessment form so each entity type has its own impact fields, MS affected, and sector-specific data. Global fields (description, suspected malicious) remain incident-level.

---

## 1. Problem

Currently, all selected entity types share the same impact values (service, data, safety, financial, persons, duration) and MS affected. In reality, a single incident can affect different entity types with different severity and geographic scope. For example, a SCADA compromise may cause service unavailability for electricity in LU+DE but only service degradation for drinking water in LU only. The malicious nature, however, is a property of the incident itself.

## 2. Field Classification

### Global (incident-level)
- Description (text)
- Suspected malicious (boolean)
- Physical access breach (boolean)

### Per-entity-type
- MS affected (multi-select)
- Service impact
- Data impact
- Safety impact
- Financial impact
- Affected persons count
- Impact duration (hours)
- Sector-specific fields (only for types in sectors with LU thresholds)

---

## 3. Form Restructure

### Step 1 — Incident Context (global)

- Description (textarea)
- Affected entity types (multi-select checkboxes, unchanged from current)
- Suspected malicious (checkbox) — **moved here from Step 2**
- Physical access breach (checkbox) — **moved here from Step 2**

### Step 2 — Per-Type Impact (dynamic, one fieldset per selected entity type)

- Rendered via HTMX when entity type checkboxes change in Step 1
- New HTMX endpoint: `GET /htmx/impact-fields/?types=energy:electricity_undertaking,drinking_water:drinking_water_supplier`
- Returns stacked fieldsets, one per type, each labeled: **"Impact — Energy / Electricity undertaking"**
- Each fieldset contains:
  - MS affected (multi-select, size=4)
  - Service impact (select)
  - Data impact (select)
  - Safety impact (select)
  - Financial impact (select)
  - Affected persons count (integer)
  - Impact duration hours (integer)
  - Sector-specific fields (inline within the fieldset, only if that type's sector is in `SECTORS_WITH_SPECIFIC_FIELDS`)
- Field names use index prefix: `impact_0_service_impact`, `impact_1_service_impact`, etc.
- Index corresponds to order of selected entity types
- Hidden field `impact_0_type` = `energy:electricity_undertaking` to map index to type

### Step 3 removed

Sector-specific fields are now inline within each type's Step 2 fieldset. The step indicator changes from 4 steps to 3: Context → Impact → Result.

### Single entity type fast path

When only one entity type is registered, Step 2 renders a single fieldset without the entity type header (same UX as current, minus suspected malicious which is now in Step 1).

---

## 4. Data Model Changes

### Assessment model — new field

```python
per_type_impacts = models.JSONField(
    default=list, blank=True,
    help_text="Per-entity-type impact data",
)
```

Structure:
```json
[
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
    "sector_specific": {"pods_affected": 1200, "voltage_level": "hv_ehv"}
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
    "sector_specific": {}
  }
]
```

### Backward compatibility

- Existing flat impact fields (`service_impact`, `data_impact`, etc.) remain on Assessment
- Populated from the **most severe** type's impacts (for dashboard display and legacy views)
- `suspected_malicious` and `physical_access_breach` stay as global fields (already top-level on Assessment)

### Migration

- Add `per_type_impacts` field (schema migration)
- Data migration: for existing assessments, populate `per_type_impacts` from flat impact fields + `affected_entity_types`

---

## 5. Assessment Engine Changes

### `run_multi_entity_assessment()` updated signature

```python
def run_multi_entity_assessment(
    description: str,
    per_type_impacts: list[dict],
    ms_established: str = "EU",
    suspected_malicious: bool = False,
) -> dict:
```

- Each entry in `per_type_impacts` contains sector, entity_type, ms_affected, all impact fields, and sector_specific
- The function calls `run_entity_assessment()` per type with **that type's specific impacts**
- Per-type `cross_border` derived from that type's `ms_affected` vs `ms_established`
- `suspected_malicious` passed globally to all types (incident-level property)

---

## 6. View Changes

### `assessment_form_view`

- Step 1 form (`AssessmentStep1Form`): add `suspected_malicious` and `physical_access_breach` fields
- Step 2 form: replaced by dynamic per-type parsing from POST data (indexed field names)
- Remove `AssessmentStep2Form` and `AssessmentStep3Form` — replaced by HTMX-rendered fields parsed directly from `request.POST`
- Parsing logic: iterate `impact_0_type`, `impact_1_type`, ... to reconstruct per_type_impacts list

### New HTMX endpoint

- `GET /htmx/impact-fields/?types=energy:electricity_undertaking,drinking_water:drinking_water_supplier`
- Returns HTML with stacked fieldsets, each with indexed field names
- Includes sector-specific fields inline when applicable

### Remove old endpoint

- Remove `/htmx/sector-fields/` (replaced by impact-fields)

---

## 7. MISP Export Changes

### `build_misp_event_global()`

Each per-type object uses **that type's impact values** from `per_type_impacts`:
- `service-impact`, `data-impact`, `safety-impact`, `financial-impact` — from per-type data
- `affected-persons-count`, `impact-duration-hours` — from per-type data
- `ms-affected` — per-type MS list, comma-joined
- `suspected-malicious` — global (from assessment)
- `description` — global (from assessment)
- Sector-specific attributes — from per-type `sector_specific`

### `build_misp_event_for_type()`

Updated to accept per-type impact data (already structured this way in `assessment_results`).

### Legacy `build_misp_event()`

Unchanged — used for old assessments without `per_type_impacts`.

---

## 8. Result Page Changes

### Impact summary

Replace the single shared impact table with **per-type impact sections**:
- One card per entity type showing its specific impacts
- Or: a table with types as rows and impact categories as columns (compact view)

Recommendation: per-type cards consistent with the per-type result cards already shown.

---

## 9. PDF Changes

Impact summary section becomes per-type, matching the result page layout.

---

## 10. Files Changed

| File | Action | Change |
|---|---|---|
| `entity/models.py` | Modify | Add `per_type_impacts` JSONField to Assessment |
| `entity/migrations/` | Create | Schema + data migration |
| `entity/forms.py` | Modify | Move malicious/breach to Step1Form, remove Step2Form/Step3Form |
| `entity/views.py` | Modify | Parse per-type impacts from POST, update assessment_form_view, new HTMX endpoint, remove old sector-fields endpoint |
| `entity/urls.py` | Modify | Replace sector-fields URL with impact-fields |
| `entity/assessment.py` | Modify | Update `run_multi_entity_assessment()` to accept per-type impacts |
| `entity/misp_export.py` | Modify | Per-type impacts in MISP objects |
| `templates/entity/assessment_form.html` | Rewrite | 3-step form, global fields in Step 1, per-type in Step 2 |
| `templates/entity/partials/impact_fields.html` | Create | HTMX partial for per-type impact fieldsets |
| `templates/entity/partials/sector_fields.html` | Remove | Replaced by inline fields in impact_fields.html |
| `templates/entity/assessment_result.html` | Modify | Per-type impact display |
| `templates/entity/assessment_pdf.html` | Modify | Per-type impact sections |

---

## 11. Out of Scope

- Per-type description (description is always incident-level)
- Drag-and-drop reordering of entity types
- Copy impact values from one type to another (nice-to-have for later)
- Different physical access breach per type (stays global)
