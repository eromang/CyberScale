# Art. 27 Entity Registration & MISP Entity Profile

## Summary

Extend the Entity model with Art. 27 NIS2 registration fields (address, contacts, responsible person, technical contact, IP ranges, MS service provision). Introduce a `cyberscale-entity-profile` MISP object as a standalone event. Link assessment events to the profile event via object references. Move all MISP push operations to admin-only actions. Add a local MISP instance to Docker Compose for real integration testing.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Field scope | Strict Art. 27 compliance | All directive-mandated fields |
| ENISA export | Deferred | Not part of this work |
| MISP linking | Separate profile event + UUID reference | Cleaner data model, no duplication |
| Profile push trigger | Admin action (Django admin) | Gatekeeping — admin reviews before push |
| Assessment push trigger | Admin action (Django admin) | Consistent with profile push |
| Profile editing | Entity user edits freely, admin pushes | Self-service editing, admin controls external actions |
| IP ranges input | Textarea, one CIDR/line, validated | Simple, `ipaddress.ip_network()` validation |
| Push ordering | Profile must be pushed before assessments | Assessment references must resolve in MISP |
| Object template governance | Custom standalone objects | Playground scope — no submission to MISP default template registry yet |

## 1. Entity Model Extensions

11 new fields on `Entity`:

```python
# Art. 27 -- Address & contact
address = models.TextField(blank=True)
contact_email = models.EmailField(blank=True)
contact_phone = models.CharField(max_length=50, blank=True)

# Art. 27 -- Responsible person (legal/management)
responsible_person_name = models.CharField(max_length=255, blank=True)
responsible_person_email = models.EmailField(blank=True)

# Art. 27 -- Technical contact (operational/incident response)
technical_contact_name = models.CharField(max_length=255, blank=True)
technical_contact_email = models.EmailField(blank=True)
technical_contact_phone = models.CharField(max_length=50, blank=True)

# Art. 27 -- IP ranges (validated CIDR, stored as JSON list)
ip_ranges = models.JSONField(default=list, blank=True)

# Art. 27 -- MS where services are provided (list of MS codes)
ms_services = models.JSONField(default=list, blank=True)

# MISP profile tracking
misp_profile_event_uuid = models.CharField(max_length=36, blank=True)
```

`ms_services` stores a list of MS codes (e.g. `["LU", "BE", "DE"]`). `ms_established` remains unchanged -- it is where the entity is established, `ms_services` is where they provide services.

## 2. Profile Editing UI

**Route:** `/profile/edit/` (GET + POST, `@login_required`)

**Form:** `EntityProfileForm` (ModelForm) with grouped fieldsets:

1. **Organisation** -- `organisation_name`, `address` (`ms_established` read-only display)
2. **General Contact** -- `contact_email`, `contact_phone`
3. **Responsible Person** -- `responsible_person_name`, `responsible_person_email`
4. **Technical Contact** -- `technical_contact_name`, `technical_contact_email`, `technical_contact_phone`
5. **Service Provision** -- `ms_services` (multi-select checkboxes, 27 EU MS)
6. **IP Ranges** -- textarea, one CIDR per line, validated with `ipaddress.ip_network(strict=False)`
7. **MISP Settings** -- `misp_instance_url`, `misp_api_key`, `misp_default_tlp`

**Validation:** IP ranges field cleaned in `clean_ip_ranges()` -- splits by newline, strips whitespace, validates each non-empty line with `ipaddress.ip_network()`, returns JSON list. Malformed entries produce a form error listing the invalid lines.

**Template:** `templates/entity/profile_edit.html` (extends `base.html`, Pico CSS fieldsets).

**Dashboard:** Add "Edit Profile" button to the existing profile card in `dashboard.html`.

Save redirects to dashboard with success message.

## 3. MISP Entity Profile Object

New builder module: `entity/misp_profile_export.py`

### Object: `cyberscale-entity-profile`

Attributes:

| Attribute | MISP type | Source |
|---|---|---|
| `organisation-name` | text | `entity.organisation_name` |
| `address` | text | `entity.address` |
| `contact-email` | email-src | `entity.contact_email` |
| `contact-phone` | phone-number | `entity.contact_phone` |
| `responsible-person-name` | text | `entity.responsible_person_name` |
| `responsible-person-email` | email-src | `entity.responsible_person_email` |
| `technical-contact-name` | text | `entity.technical_contact_name` |
| `technical-contact-email` | email-src | `entity.technical_contact_email` |
| `technical-contact-phone` | phone-number | `entity.technical_contact_phone` |
| `ms-established` | text | `entity.ms_established` |
| `ms-services` | text | comma-separated `entity.ms_services` |
| `ip-range` | ip-src | one attribute per CIDR (repeatable) |
| `sector` | text | one per registered EntityType (repeatable) |
| `entity-type` | text | one per registered EntityType (repeatable) |

### Event structure

```json
{
  "Event": {
    "info": "CyberScale entity profile: <org name>",
    "threat_level_id": "4",
    "analysis": "2",
    "distribution": "1",
    "uuid": "<entity.misp_profile_event_uuid>",
    "Tag": [
      {"name": "cyberscale:type=\"entity-profile\""},
      {"name": "<entity.misp_default_tlp>"}
    ],
    "Object": [{
      "name": "cyberscale-entity-profile",
      "meta-category": "misc",
      "uuid": "<generated>",
      "Attribute": [...]
    }]
  }
}
```

`threat_level_id: 4` (undefined) -- this is a profile, not a threat.

Builder function: `build_misp_profile_event(entity) -> dict`

## 4. MISP Linking -- Assessment References Profile

When an assessment event is pushed and the entity has `misp_profile_event_uuid`, each `cyberscale-entity-assessment` object includes an object reference:

```json
{
  "ObjectReference": [{
    "referenced_uuid": "<entity.misp_profile_event_uuid>",
    "relationship_type": "belongs-to",
    "comment": "Entity profile for this assessment"
  }]
}
```

### Implementation

- `entity/misp_export.py`: `build_misp_event_global`, `build_misp_event`, `build_misp_event_for_type` gain optional `profile_event_uuid` parameter. When set, each object dict includes `ObjectReference`.
- `entity/misp_push.py`: `_dict_to_misp_event` handles `ObjectReference` when building `MISPObject`.
- If no profile UUID exists, assessment push works as before -- no reference, no error.

## 5. Admin-Only MISP Push

All MISP push operations move to Django admin actions. The user-facing "Push to MISP" button in `assessment_result.html` is removed. The existing `assessment_misp_push_view` and its URL route are removed.

### Admin actions

**EntityAdmin -- "Push profile to MISP":**
1. Validate `misp_instance_url` + `misp_api_key` present
2. Build profile event via `build_misp_profile_event(entity)`
3. Push via `push_event()` (reuse existing module)
4. On success: store/update `misp_profile_event_uuid`, create `Submission(target="misp_profile_push", status="success")`
5. On failure: create `Submission(target="misp_profile_push", status="failed")`, show error
6. Subsequent pushes use `update_event` (same UUID) to update the existing MISP event rather than creating a new one. First push uses `add_event`, subsequent pushes use `update_event`.

**AssessmentAdmin -- "Push to MISP":**
1. Validate entity has `misp_instance_url` + `misp_api_key`
2. Validate entity has `misp_profile_event_uuid` -- error if not: "Entity profile must be pushed to MISP before pushing assessments"
3. Build assessment event with `profile_event_uuid` parameter
4. Push via `push_event()`
5. Create `Submission(target="misp_push", ...)`

### Submission model update

Add `misp_profile_push` to `TARGET_CHOICES`:

```python
TARGET_CHOICES = [
    ("pdf_download", "PDF Download"),
    ("misp_json_download", "MISP JSON Download"),
    ("misp_push", "MISP Push"),
    ("misp_profile_push", "MISP Profile Push"),
]
```

## 6. MS Affected Filtering

When the entity has `ms_services` populated, the per-type impact form's "MS affected" checkboxes are filtered to `ms_services | {ms_established}`.

- `entity/views.py` `impact_fields_view`: compute `allowed_ms` from entity's `ms_services + [ms_established]`, pass to template context.
- `templates/entity/partials/impact_fields.html`: render only allowed MS as checkboxes. If `allowed_ms` is empty (profile not filled), render all 27 MS.
- Server-side validation in `_parse_per_type_impacts`: reject any MS not in the allowed set when `ms_services` is populated.

## 7. Admin Interface Updates

**EntityAdmin:**
- `fieldsets` grouping: Organisation, Contact, Responsible Person, Technical Contact, Service Provision, IP Ranges, MISP Settings
- `list_display`: add `contact_email`, `responsible_person_name`
- `readonly_fields`: `misp_profile_event_uuid`
- Action: "Push profile to MISP"

**AssessmentAdmin:**
- Action: "Push to MISP"
- `readonly_fields`: `misp_event_uuid`
- `list_filter`: add `status`

## 8. Docker Compose -- Local MISP Instance

Add MISP to `docker-compose.yml` for real integration testing:

- **misp** container: `ghcr.io/misp/misp-docker` (official image)
- **misp-db** container: MySQL 8 (MISP backend)
- **redis** container: Redis (MISP caching)
- Auto-configured with default admin credentials and API key
- CyberScale web container gets `MISP_URL` and `MISP_API_KEY` environment variables
- Health check on MISP before tests run

Integration tests run against the real MISP instance for actual push/verify workflows.

## 9. Testing

### Unit tests (no MISP needed)

**`entity/tests/test_profile.py`:**
- Profile edit form loads with all Art. 27 fields
- Profile save persists all fields correctly
- IP ranges: valid CIDRs accepted (`192.168.1.0/24`, `10.0.0.0/8`, `2001:db8::/32`)
- IP ranges: malformed entries rejected with error message
- IP ranges: empty textarea saves as empty list
- MS services: multi-select saves as JSON list
- Profile edit requires login

**`entity/tests/test_views.py` (extend):**
- MS affected filtering: only allowed MS rendered when `ms_services` set
- MS affected fallback: all 27 MS when `ms_services` empty
- Server-side rejection of MS not in allowed set

### Integration tests (against Docker MISP)

**`entity/tests/test_misp_integration.py`:**
- Push profile to MISP via admin action, verify event created
- Push profile again, verify event updated (same UUID)
- Push assessment blocked when no profile UUID
- Push assessment after profile push, verify event created with object reference
- Verify object reference resolves to profile event UUID
- Push with invalid credentials fails gracefully

### Existing test updates

**`entity/tests/test_misp_push.py`:**
- Remove user-facing push view tests (view removed)
- Keep/adapt module-level push tests (mock-based)
- Add profile push module tests
- Add object reference tests

## 10. Files Changed

| File | Change |
|---|---|
| `entity/models.py` | 11 new Entity fields + Submission target choice |
| `entity/migrations/0006_*.py` | New migration for Art. 27 fields |
| `entity/forms.py` | New `EntityProfileForm` with CIDR validation |
| `entity/views.py` | Add `profile_edit_view`, remove `assessment_misp_push_view`, update `impact_fields_view` for MS filtering |
| `entity/urls.py` | Add `/profile/edit/`, remove `/assess/<pk>/misp-push/` |
| `entity/misp_profile_export.py` | New -- `build_misp_profile_event()` |
| `entity/misp_export.py` | Add `profile_event_uuid` param + ObjectReference |
| `entity/misp_push.py` | Handle ObjectReference in `_dict_to_misp_event` |
| `entity/admin.py` | Fieldsets, push actions, readonly fields |
| `templates/entity/profile_edit.html` | New -- profile edit form |
| `templates/entity/dashboard.html` | Add "Edit Profile" button |
| `templates/entity/assessment_result.html` | Remove "Push to MISP" button |
| `templates/entity/partials/impact_fields.html` | MS affected filtering |
| `docker-compose.yml` | Add MISP + MySQL + Redis containers |
| `entity/tests/test_profile.py` | New -- profile form/validation tests |
| `entity/tests/test_misp_integration.py` | New -- real MISP integration tests |
| `entity/tests/test_misp_push.py` | Adapt for admin-only push |
| `requirements-web.txt` | Already has pymisp |
