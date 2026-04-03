# MISP JSON Export + UI Polish — Design Spec

**Date:** 2026-04-03
**Status:** Approved
**Scope:** v1.0 playground — MISP JSON download + professional UI overhaul

---

## 1. MISP JSON Export

### Endpoint

`GET /assess/<pk>/misp-json/` — returns downloadable JSON file.

### MISP Event Structure

Follows product spec section 6.2:

```json
{
  "Event": {
    "info": "CyberScale entity assessment: energy / electricity_undertaking",
    "date": "2026-04-03",
    "threat_level_id": "2",
    "analysis": "2",
    "distribution": "1",
    "uuid": "<assessment-uuid>",
    "tags": [
      {"name": "cyberscale:phase=\"phase-2\""},
      {"name": "cyberscale:significance-model=\"national_lu_thresholds\""},
      {"name": "nis2:significance=\"significant\""},
      {"name": "tlp:amber"}
    ],
    "Object": [
      {
        "name": "cyberscale-entity-assessment",
        "meta-category": "misc",
        "uuid": "<object-uuid>",
        "Attribute": [
          {"object_relation": "sector", "type": "text", "value": "energy"},
          {"object_relation": "entity-type", "type": "text", "value": "electricity_undertaking"},
          {"object_relation": "ms-established", "type": "text", "value": "LU"},
          {"object_relation": "description", "type": "text", "value": "..."},
          {"object_relation": "service-impact", "type": "text", "value": "unavailable"},
          {"object_relation": "data-impact", "type": "text", "value": "compromised"},
          {"object_relation": "safety-impact", "type": "text", "value": "health_risk"},
          {"object_relation": "financial-impact", "type": "text", "value": "significant"},
          {"object_relation": "affected-persons-count", "type": "counter", "value": "50000"},
          {"object_relation": "impact-duration-hours", "type": "counter", "value": "4"},
          {"object_relation": "suspected-malicious", "type": "boolean", "value": "1"},
          {"object_relation": "significant-incident", "type": "boolean", "value": "1"},
          {"object_relation": "significance-model", "type": "text", "value": "national_lu_thresholds"},
          {"object_relation": "triggered-criteria", "type": "text", "value": "..."},
          {"object_relation": "competent-authority", "type": "text", "value": "ILR"},
          {"object_relation": "framework", "type": "text", "value": "NIS2 (ILR)"},
          {"object_relation": "early-warning-recommended", "type": "boolean", "value": "1"},
          {"object_relation": "early-warning-deadline", "type": "text", "value": "24h"}
        ]
      }
    ]
  }
}
```

### Implementation Details

- UUID: generated on first MISP export, stored in `Assessment.misp_event_uuid`
- `threat_level_id`: mapped from significance (1=High if significant, 3=Low if not, 2=Medium if undetermined)
- `analysis`: always "2" (completed)
- `distribution`: "1" (community) — entity can change TLP in their profile
- Triggered criteria joined with `" | "` separator for the text attribute
- Response: `Content-Type: application/json`, `Content-Disposition: attachment`
- Records `Submission(target="misp_json_download", status="success")`

### Files Changed

- `entity/views.py` — new `assessment_misp_json_view`
- `entity/urls.py` — new URL pattern
- Templates — add "Download MISP JSON" button to result page and dashboard

---

## 2. UI Polish — Professional/Institutional

### Color Palette

| Token | Hex | Usage |
|---|---|---|
| Primary (navy) | `#1a237e` | Headers, nav, primary buttons |
| Primary light | `#283593` | Hover states, active nav |
| Secondary (steel) | `#455a64` | Body text, secondary elements |
| Background | `#f8f9fa` | Page background |
| Surface | `#ffffff` | Cards, forms |
| Significant (red) | `#c62828` | Significant badge, alerts |
| Not significant (green) | `#2e7d32` | Not significant badge |
| Undetermined (amber) | `#f9a825` | Undetermined badge |
| Warning recommended | `#c62828` | Early warning recommended |
| Border | `#dee2e6` | Card borders, table borders |

### Navigation

- Navy background, white text
- Left: "CyberScale" brand with a shield-like accent (CSS only, no image)
- Right: nav links (Dashboard, New Assessment, Logout)
- Compact, no unnecessary height

### Registration Form

- HTMX sector filtering: selecting a sector fetches entity types via `/htmx/entity-types/?sector=X` and populates the entity type dropdown — already wired in views, needs the `hx-` attributes to work correctly
- Clean fieldset grouping: Account / Entity Profile
- MS dropdown pre-selects nothing (forces explicit choice)

### Assessment Form

- Step indicators: numbered badges (1-4) with titles, current step highlighted
- Step 3 (sector-specific): only shown when relevant sector is selected — use `<details>` but improve styling
- Better grid layout for impact fields
- Submit button with clear "Run Assessment" label

### Result Page

- Top banner: full-width significance determination with large badge, framework, authority
- Cards below in 2-column grid: Triggered Criteria | Early Warning
- Full-width cards: Impact Summary | Incident Description
- Action bar at bottom: Download PDF | Download MISP JSON | Back to Dashboard
- Disclaimer at very bottom, muted

### Dashboard

- Entity profile summary card at top
- Assessment table: cleaner styling, row hover, status badges with consistent colors
- Action links: View | PDF | MISP JSON
- "New Incident Assessment" prominent button

### PDF

- Match web color scheme: navy headers (#1a237e), same severity colors
- Professional header with rule line
- Clean table styling matching the institutional feel

### Static CSS

- `static/css/cyberscale.css` — custom overrides on top of Pico CSS
- Pico CSS remains via CDN (no build step)
- All custom styles scoped to CyberScale-specific classes

### Files Changed

- `templates/base.html` — new nav, color scheme, custom CSS link
- `templates/entity/register.html` — HTMX filtering fix, better fieldsets
- `templates/entity/assessment_form.html` — step indicators, improved layout
- `templates/entity/assessment_result.html` — card layout, MISP JSON button
- `templates/entity/dashboard.html` — cleaner table, MISP JSON links
- `templates/entity/login.html` — minor styling alignment
- `templates/entity/assessment_pdf.html` — navy color scheme
- `static/css/cyberscale.css` — new file with all custom styles

---

## 3. Out of Scope

- MISP push (requires PyMISP + MISP instance)
- Save draft functionality
- MISP object template validation
- Authentication/SSO beyond Django auth
- REST API
