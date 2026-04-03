# Authority & CSIRT Registry (v1.2)

## Summary

Introduce `CompetentAuthority` and `CSIRT` as separate Django models with contact details and notification routing. Seed from reference JSON. Auto-assign to EntityType records based on sector + MS, with admin override support. Replace hardcoded `_determine_competent_authority()` with FK-based lookup. Add CSIRT and notification recipient to assessment results and MISP export.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| CA vs CSIRT models | Separate models | LU complexity (ILR, CSSF, CIRCL, GOVCERT.LU — all distinct) |
| MISP credentials | Global (env vars) | One MISP-A per deployment, sync handles distribution |
| Reference data seeding | JSON + management command | Consistent with `nis2_entity_types.json` pattern |
| Entity type → authority | FK on EntityType, auto-assigned | Visible in admin, queryable, overridable |
| MS scope | Per-entity (`ms_established`) | Flexible for multi-MS deployments |
| Notification path | Reference data flag (`receives_notifications`) | Version-controlled, no extra model |
| Exception handling | Admin override with `auto_assigned` flag | Some entities supervised by non-default authority |

## 1. Data Models

### CompetentAuthority

```python
class CompetentAuthority(models.Model):
    name = models.CharField(max_length=255)           # "Institut Luxembourgeois de Régulation"
    abbreviation = models.CharField(max_length=20)     # "ILR"
    ms = models.CharField(max_length=10)              # "LU"
    sectors = models.JSONField(default=list)           # ["energy", "transport", ...] or ["*"]
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)     # Notification portal URL
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name_plural = "competent authorities"
```

### CSIRT

```python
class CSIRT(models.Model):
    name = models.CharField(max_length=255)           # "CIRCL"
    abbreviation = models.CharField(max_length=20)     # "CIRCL"
    ms = models.CharField(max_length=10)              # "LU"
    website = models.URLField(blank=True)
    notification_url = models.URLField(blank=True)
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=50, blank=True)
    emergency_phone = models.CharField(max_length=50, blank=True)  # 24/7 incident line
    receives_notifications = models.BooleanField(default=False)

    class Meta:
        unique_together = ("abbreviation", "ms")
        verbose_name_plural = "CSIRTs"
```

### EntityType additions

```python
# Add to existing EntityType model
competent_authority = models.ForeignKey(
    "CompetentAuthority", null=True, blank=True, on_delete=models.SET_NULL
)
csirt = models.ForeignKey(
    "CSIRT", null=True, blank=True, on_delete=models.SET_NULL
)
ca_auto_assigned = models.BooleanField(default=True)
csirt_auto_assigned = models.BooleanField(default=True)
```

## 2. Reference Data

File: `data/reference/authorities.json`

```json
{
  "version": "1.0",
  "competent_authorities": [
    {
      "abbreviation": "ILR",
      "name": "Institut Luxembourgeois de Régulation",
      "ms": "LU",
      "sectors": ["energy", "transport", "drinking_water", "health",
                   "digital_infrastructure", "ict_service_management",
                   "space", "waste_water", "postal_courier",
                   "chemicals", "food", "manufacturing",
                   "digital_providers", "research"],
      "website": "https://web.ilr.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "CSSF",
      "name": "Commission de Surveillance du Secteur Financier",
      "ms": "LU",
      "sectors": ["banking", "financial_market"],
      "website": "https://www.cssf.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "CCB",
      "name": "Centre for Cybersecurity Belgium",
      "ms": "BE",
      "sectors": ["*"],
      "website": "https://ccb.belgium.be",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    },
    {
      "abbreviation": "BNB",
      "name": "Banque Nationale de Belgique",
      "ms": "BE",
      "sectors": ["banking", "financial_market"],
      "website": "https://www.nbb.be",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "receives_notifications": true
    }
  ],
  "csirts": [
    {
      "abbreviation": "CIRCL",
      "name": "Computer Incident Response Center Luxembourg",
      "ms": "LU",
      "website": "https://www.circl.lu",
      "notification_url": "",
      "contact_email": "info@circl.lu",
      "contact_phone": "",
      "emergency_phone": "+352 247 88444",
      "receives_notifications": false
    },
    {
      "abbreviation": "GOVCERT.LU",
      "name": "GOVCERT.LU",
      "ms": "LU",
      "website": "https://www.govcert.lu",
      "notification_url": "",
      "contact_email": "",
      "contact_phone": "",
      "emergency_phone": "",
      "receives_notifications": false
    },
    {
      "abbreviation": "CERT.be",
      "name": "CERT.be",
      "ms": "BE",
      "website": "https://cert.be",
      "notification_url": "https://notif.safeonweb.be",
      "contact_email": "cert@cert.be",
      "contact_phone": "",
      "emergency_phone": "+32 2 501 05 60",
      "receives_notifications": true
    }
  ]
}
```

`"sectors": ["*"]` means all NIS2 sectors (horizontal authority like CCB).

`receives_notifications` captures Art. 23 national implementation: in LU the CA (ILR/CSSF) receives notifications; in BE the CSIRT (CERT.be) does.

## 3. Auto-Assignment & Override Logic

### Auto-assignment flow

1. Entity registers or adds an entity type
2. `assign_authority(entity_type)` called:
   - Find CA where `ms == entity.ms_established` and (`sector in ca.sectors` or `"*" in ca.sectors`)
   - If multiple CAs match: most specific wins (exact sector match takes priority over wildcard `"*"`)
   - Same logic for CSIRT: find CSIRT where `ms == entity.ms_established`
   - If multiple CSIRTs in same MS (e.g., LU: CIRCL for private sector, GOVCERT.LU for government): assign first match from JSON order; admin overrides for exceptions (e.g., government entities → GOVCERT.LU)
3. Set `ca_auto_assigned = True`, `csirt_auto_assigned = True`

### Admin override

- Admin changes CA or CSIRT FK via dropdown (filtered to same MS)
- `ca_auto_assigned` / `csirt_auto_assigned` set to `False` on save
- Override persists: `seed_authorities` and `assign_authorities` skip manually overridden records
- Admin action "Re-assign authority automatically" resets `auto_assigned` flags and re-runs assignment

### Priority resolution

For CAs, when sector matches multiple authorities in the same MS:
1. Exact sector match (e.g., "banking" → CSSF) wins over wildcard
2. If two exact matches exist (shouldn't happen in well-formed data), first in JSON order wins

## 4. Assessment Engine Changes

### Remove

`_determine_competent_authority(ms, sector)` function in `entity/assessment.py`

### Replace with

Direct FK read in `run_entity_assessment()` and `run_multi_entity_assessment()`. The entity_type record carries the assigned CA and CSIRT.

### Assessment result additions

| Field | Source | Description |
|---|---|---|
| `csirt` | `entity_type.csirt.abbreviation` | Assigned CSIRT (new) |
| `authority_override` | `not entity_type.ca_auto_assigned` | Whether CA was manually overridden |
| `notification_recipient` | CA or CSIRT with `receives_notifications=True` | Who the entity should notify |
| `notification_contact` | Email/URL from the notification recipient | Concrete contact info |

### Early warning text change

Before: "Submit early warning to competent authority or CSIRT within 24 hours"

After: "Submit early warning to **{recipient_name}** ({notification_url or contact_email}) within 24 hours per NIS2 Art. 23(4)(a)."

## 5. MISP Export Additions

`cyberscale-entity-assessment` object template gains two attributes:

| Attribute | Type | Description |
|---|---|---|
| `csirt` | text | Assigned CSIRT abbreviation |
| `notification-recipient` | text | Who receives Art. 23 notifications |

Template version bumped to 2. Template definition in `data/misp-objects/cyberscale-entity-assessment/definition.json` updated. MISP instances need `updateObjectTemplates` re-run.

## 6. Management Commands

### `seed_authorities`

- Reads `data/reference/authorities.json`
- `update_or_create` by `(abbreviation, ms)` for both CAs and CSIRTs
- Idempotent: updates contact details, doesn't overwrite model fields not in JSON
- Added to `setup_playground` command chain

### `assign_authorities`

- Iterates all EntityType records
- For records with `ca_auto_assigned=True`: look up and assign CA from sector + MS
- For records with `csirt_auto_assigned=True`: look up and assign CSIRT from MS
- Called after `seed_authorities` and after entity type creation
- Skips manually overridden assignments

## 7. Admin Interface

### CompetentAuthorityAdmin

- `list_display`: abbreviation, name, ms, receives_notifications
- `list_filter`: ms
- `search_fields`: name, abbreviation

### CSIRTAdmin

- `list_display`: abbreviation, name, ms, receives_notifications, emergency_phone
- `list_filter`: ms
- `search_fields`: name, abbreviation

### EntityTypeAdmin (enhanced)

- Add `competent_authority`, `csirt`, `ca_auto_assigned`, `csirt_auto_assigned` to display
- CA/CSIRT dropdowns filtered by entity's MS
- Custom action: "Re-assign authority automatically"

### EntityAdmin (enhanced)

- EntityType inline shows CA + CSIRT columns

### Dashboard / Profile

- Entity profile page shows assigned CA + CSIRT per entity type (read-only for entity users)
- Assessment result page shows notification recipient with contact details

## 8. Testing

### Unit tests

**`entity/tests/test_authorities.py`:**
- CA and CSIRT model creation + unique constraint
- `seed_authorities` loads JSON, idempotent re-run
- `seed_authorities` updates contact details without overwriting manual overrides
- Auto-assignment: exact sector match
- Auto-assignment: wildcard `"*"` match
- Auto-assignment: most-specific-wins priority (CSSF over ILR for banking in LU)
- Manual override persists after `assign_authorities`
- Re-assign action resets to auto

**Assessment engine tests:**
- Assessment reads CA from FK
- Assessment reads CSIRT from FK
- Result includes `csirt`, `authority_override`, `notification_recipient`
- Early warning text includes concrete contact details
- Entity with no assigned authority gets empty strings (graceful fallback)

**MISP export tests:**
- Assessment event includes `csirt` attribute
- Assessment event includes `notification-recipient` attribute

## 9. Files Changed

| File | Change |
|---|---|
| `entity/models.py` | Add `CompetentAuthority`, `CSIRT` models; add FKs + `auto_assigned` to `EntityType` |
| `entity/migrations/0007_*.py` | New migration |
| `data/reference/authorities.json` | New — CA + CSIRT reference data |
| `entity/management/commands/seed_authorities.py` | New — load from JSON |
| `entity/management/commands/assign_authorities.py` | New — auto-assign FKs |
| `entity/management/commands/setup_playground.py` | Add `seed_authorities` + `assign_authorities` to chain |
| `entity/assessment.py` | Remove `_determine_competent_authority()`, read from FK, add CSIRT + notification recipient |
| `entity/admin.py` | Add `CompetentAuthorityAdmin`, `CSIRTAdmin`, enhance `EntityTypeAdmin` |
| `entity/views.py` | Call `assign_authority()` on entity type creation |
| `entity/misp_export.py` | Add `csirt` and `notification-recipient` attributes |
| `data/misp-objects/cyberscale-entity-assessment/definition.json` | Add `csirt`, `notification-recipient` attrs, bump version |
| `templates/entity/assessment_result.html` | Show notification recipient with contact details |
| `templates/entity/dashboard.html` | Show CA + CSIRT per entity type |
| `entity/tests/test_authorities.py` | New — full test suite |
| `src/cyberscale/models/early_warning.py` | Parameterize notification text with recipient details |
