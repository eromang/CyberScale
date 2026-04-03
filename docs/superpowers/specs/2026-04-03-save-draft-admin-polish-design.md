# Save Draft + Django Admin Polish — Design Spec

**Date:** 2026-04-03
**Status:** Approved
**Scope:** v1.0 playground — save/resume draft assessments + admin improvements

---

## 1. Save Draft

### Behavior

- Assessment form gets a second submit button: "Save Draft" (secondary style), alongside "Run Assessment"
- When "Save Draft" is clicked, all form fields are saved to an Assessment record with `status="draft"`
- The assessment engine is **not** run — result fields stay empty
- Redirect to dashboard with a success message

### Resume

- New view at `GET /assess/draft/<pk>/` — loads draft data into the assessment form
- Form is pre-populated with all saved fields (description, impacts, sector-specific, MS affected)
- Submitting the resumed form with "Run Assessment" runs the engine, updates the existing Assessment record to `status="completed"`, and populates result fields
- Submitting with "Save Draft" updates the draft (no new record)

### Delete Draft

- New view at `POST /assess/draft/<pk>/delete/` — deletes the draft Assessment
- Only drafts can be deleted (completed assessments cannot)
- Small "Delete" link on dashboard next to draft assessments
- Requires confirmation via POST (no GET delete)

### Dashboard Changes

- Draft assessments show a `DRAFT` badge (grey/steel color) instead of significance badge
- Actions column: "Resume" link for drafts (instead of "View"), no PDF/MISP links for drafts
- Drafts sort above completed assessments (most recent first within each group)

### Files Changed

- `entity/views.py` — new `save_draft_view` logic (integrated into `assessment_form_view`), new `resume_draft_view`, new `delete_draft_view`
- `entity/urls.py` — two new URL patterns
- `templates/entity/assessment_form.html` — add "Save Draft" button, accept initial data for pre-fill
- `templates/entity/dashboard.html` — draft badge, resume/delete links, conditional actions

---

## 2. Django Admin Polish

### Entity Admin

- Add `AssessmentInline` (TabularInline, readonly, last 10 assessments)
- Inline fields: `id`, `created_at`, `status`, `result_significance_label`, `result_model`, `result_framework`
- All inline fields readonly (admin views assessments, doesn't edit them)
- Add `user__username` to search_fields

### Assessment Admin

- **list_display:** `id`, `entity`, `status`, `result_significance_label`, `result_framework`, `result_competent_authority`, `result_model`, `created_at`
- **list_filter:** `status`, `result_significance_label`, `result_model`, `result_framework`, `sector`
- **search_fields:** `entity__organisation_name`, `description`
- **date_hierarchy:** `created_at`
- **readonly_fields:** all result fields (`result_significance`, `result_significance_label`, `result_model`, `result_criteria`, `result_framework`, `result_competent_authority`, `result_early_warning`, `result_raw`)
- **Custom action:** "Export selected as CSV" — exports selected assessments as CSV download with key fields (id, entity, sector, entity_type, significance, framework, authority, model, created_at)

### Submission Admin

- **date_hierarchy:** `submitted_at`
- **list_display:** add `assessment__entity` for context
- **raw_id_fields:** `assessment` (for performance with many records)

### Files Changed

- `entity/admin.py` — rewrite with inlines, improved list views, CSV export action

---

## 3. Out of Scope

- Custom admin dashboard views (v2.1)
- Sector aggregation / statistics
- Bulk re-assessment
- Draft auto-save (JS-based)
