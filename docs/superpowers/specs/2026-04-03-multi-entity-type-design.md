# Multi-Entity-Type Support — Design Spec

**Date:** 2026-04-03
**Status:** Approved
**Scope:** v1.0 playground — entities with multiple sectors/entity types, single-form multi-type assessment

---

## 1. Problem

NIS2 entities can operate across multiple sectors (e.g., a utility that's both an electricity undertaking and a drinking water supplier). A single incident may affect multiple entity types simultaneously. The current model forces one sector/entity_type per entity and one determination per assessment. This creates either inaccurate assessments or duplicated reporting — both violate administrative simplification (NIS2 Art. 23(9)).

## 2. Solution

Entities register multiple entity types. When reporting an incident, they select all affected entity types. CyberScale runs the assessment engine per entity type behind the scenes and presents unified results — one form submission, multiple significance determinations.

---

## 3. Data Model Changes

### New model: `EntityType`

```
EntityType
├── entity (FK → Entity)
├── sector (str, max_length=100)
├── entity_type (str, max_length=100)
├── added_at (DateTimeField, auto_now_add)
```

- One Entity can have many EntityTypes
- At least one EntityType required per Entity
- Unique together: (entity, entity_type) — no duplicates

### Entity model changes

- **Remove:** `sector` and `entity_type` fields
- **Keep:** `organisation_name`, `ms_established`, `competent_authority`, MISP fields
- Access entity types via `entity.entity_types.all()`

### Assessment model changes

- **Keep:** `sector` and `entity_type` fields — stores the primary/first affected type (for backward compat and dashboard display)
- **New:** `affected_entity_types` (JSONField, default=list) — list of `{"sector": "...", "entity_type": "..."}` dicts for all affected types
- **New:** `assessment_results` (JSONField, default=list) — per-entity-type results array. Each entry:
  ```json
  {
    "sector": "energy",
    "entity_type": "electricity_undertaking",
    "significant_incident": true,
    "significance_label": "SIGNIFICANT",
    "model": "national_lu",
    "triggered_criteria": ["..."],
    "framework": "NIS2 (ILR)",
    "competent_authority": "ILR",
    "early_warning": {"recommended": true, "deadline": "24h", ...}
  }
  ```
- **Existing `result_significance` / `result_significance_label`:** reflect the **most severe** result across all entity types (for dashboard badge)
- **Existing `result_early_warning`:** reflects the **shortest deadline** across all types

### Migration strategy

- Create `EntityType` model
- Data migration: for each existing Entity with `sector`/`entity_type`, create one `EntityType` record
- Data migration: for each existing Assessment, populate `affected_entity_types` from `sector`/`entity_type` and `assessment_results` from existing result fields
- Remove `sector`/`entity_type` from Entity model

---

## 4. Registration

- Registration form unchanged: pick one sector + one entity type (via HTMX filtering)
- Creates Entity + one EntityType record
- User can add more entity types from the dashboard

---

## 5. Dashboard

### Entity types management

- Profile card shows all registered entity types as a list: `Energy / Electricity undertaking`, `Drinking Water / Drinking water supplier`
- **"Add Entity Type" button** — opens an inline HTMX form:
  - Sector dropdown (filtered to exclude already-registered sectors, or allow same sector with different type)
  - Entity type dropdown (HTMX filtered by sector, existing endpoint)
  - "Add" button → POST → adds EntityType, re-renders profile card
- **Remove entity type** — small "×" link next to each type, POST with confirmation. Cannot remove the last one.

### Assessment table

- No change to table structure — `sector`/`entity_type` columns show the primary affected type
- Badge shows the most severe significance across all types

---

## 6. Assessment Form

### Step 1 — Incident Context

- **New field: "Affected entity types"** — multi-select checkbox list of the user's registered entity types
  - Each option: `Energy / Electricity undertaking`
  - If only one entity type registered: auto-selected, shown as read-only text (not a checkbox)
  - If multiple: all unchecked by default, user selects which are affected
- Description and MS affected: unchanged

### Step 3 — Sector-Specific Fields (HTMX dynamic)

- **Rendered via HTMX** based on selected entity types in Step 1
- New HTMX endpoint: `GET /htmx/sector-fields/?sectors=energy,drinking_water`
- Returns only the sector-specific fieldsets for the selected sectors
- If no selected entity type has sector-specific fields: Step 3 is hidden entirely
- Sector-specific field mapping:
  - `energy` (LU): PODs affected, voltage level, SCADA unavailable min
  - `transport` (LU rail): trains cancelled %, slots impacted
  - `health` (LU): persons with health impact, analyses affected %
  - All others: no sector-specific fields → Step 3 hidden

### Submit behavior

- "Run Assessment" → engine runs once per selected entity type, all results stored
- "Save Draft" → saves selected entity types + form data, no engine run

---

## 7. Assessment Engine Integration

### `entity/assessment.py` changes

- New function: `run_multi_entity_assessment(...)` — takes a list of `(sector, entity_type)` tuples plus shared impact fields
- Calls `run_entity_assessment()` once per entity type
- Returns list of per-type result dicts
- Determines overall significance: most severe across all types
  - Priority: SIGNIFICANT > LIKELY > UNDETERMINED > UNCERTAIN > NOT SIGNIFICANT > UNLIKELY
- Determines overall early warning: recommended if any type recommends it, shortest deadline

### View changes

- `assessment_form_view` calls `run_multi_entity_assessment()` instead of `run_entity_assessment()`
- Stores per-type results in `assessment_results` JSON field
- Stores overall significance in existing `result_significance` / `result_significance_label`
- First affected type stored in `sector` / `entity_type` (for backward compat)

---

## 8. Result Page

- **Significance banner:** shows overall (most severe) determination
- **Per-entity-type cards:** one card per affected entity type, each showing:
  - Sector / entity type label
  - Significance badge
  - Framework + competent authority
  - Triggered criteria list
  - Early warning recommendation
- **Impact summary:** shared (one card, same as today)
- **Incident description:** shared (one card)
- **Actions:** PDF (unified), MISP JSON per entity type

---

## 9. PDF Export

- Single PDF document with all per-type results
- After the overall significance banner, a section per entity type:
  - "Entity Type: Energy / Electricity undertaking"
  - Significance, framework, authority, triggered criteria, early warning
- Impact summary and description shared at the bottom

---

## 10. MISP Export

- One MISP event JSON per affected entity type (per product spec: one event per entity assessment)
- If multiple types: download page offers individual downloads or "Download All" (zip not needed for v1.0 — just list of download links)
- Each MISP event tags reflect that specific entity type's assessment

---

## 11. Files Changed

| File | Action | Change |
|---|---|---|
| `entity/models.py` | Modify | Add `EntityType` model, add `affected_entity_types` + `assessment_results` fields to Assessment, remove `sector`/`entity_type` from Entity |
| `entity/migrations/` | Create | New migration + data migration |
| `entity/forms.py` | Modify | Add `AffectedEntityTypesForm` (multi-checkbox), update `AssessmentStep3Form` |
| `entity/views.py` | Modify | Update assessment_form_view, add HTMX sector-fields endpoint, add entity type management views |
| `entity/urls.py` | Modify | Add entity type management + sector-fields HTMX URLs |
| `entity/assessment.py` | Modify | Add `run_multi_entity_assessment()` |
| `entity/misp_export.py` | Modify | Update to handle per-type exports |
| `entity/admin.py` | Modify | Register `EntityType`, update inlines |
| `templates/entity/dashboard.html` | Modify | Entity types list, add/remove UI |
| `templates/entity/assessment_form.html` | Modify | Entity type multi-select, HTMX sector fields |
| `templates/entity/assessment_result.html` | Modify | Per-type result cards |
| `templates/entity/assessment_pdf.html` | Modify | Per-type sections |
| `templates/entity/register.html` | Minor | No change to UX, backend creates EntityType |
| `templates/entity/partials/` | Create | HTMX partial templates (entity type list, sector fields) |

---

## 12. Out of Scope

- Different impact values per entity type (one incident = one set of impacts)
- Zip download for multiple MISP events
- Automatic competent authority determination per entity type (hardcoded mapping is sufficient)
- Entity type removal cascading to assessments (assessments keep their `affected_entity_types` JSON snapshot)
