# Art. 23 Early Warning (v1.3)

## Summary

Entity submits a structured Art. 23(4)(a) early warning through cyberscale-web. The early warning is pushed to MISP-A as a `cyberscale-early-warning` object on the existing assessment event. Lifecycle state (received → acknowledged → under review → closed) lives as MISP tags (source of truth). Admin manages lifecycle via Django admin actions that update MISP tags. Entity sees current status on the result page by querying MISP-A.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Entity trigger | Entity decides (clicks "Submit Early Warning") | Assessment is advisory — notification is entity's responsibility |
| MISP structure | Object added to existing assessment event | One event = one incident; objects accumulate as lifecycle progresses |
| Lifecycle source of truth | MISP-A tags | MISP is the canonical data store |
| Form content | Pre-filled from assessment + entity confirms + support request | Minimizes entity burden |
| Authority UI for v1.3 | Django admin actions (basic) | Full authority portal deferred to v2.0 |
| Authority portal (v2.0) | Multi-tenant, role-scoped, self-hostable with own MISP | Registered as future goal |

## 1. Early Warning Form (Entity Side)

**Route:** `/assess/<pk>/early-warning/` (GET + POST, `@login_required`)

**Access:** Only for completed assessments where `result_early_warning.recommended == True` and no prior `early_warning` Submission exists.

### Form fields

| Field | Type | Source |
|---|---|---|
| Suspected malicious | Boolean (editable) | Pre-filled from assessment |
| Cross-border impact | Boolean (editable) | Pre-filled from assessment |
| Initial assessment text | Textarea (required) | Entity writes their description |
| Request CSIRT support | Boolean | Default False |
| Support description | Textarea (optional) | What kind of support needed (shown when support requested) |

### Read-only display (from assessment)

- Sector / entity type / MS established
- Impact summary (service, data, safety, financial)
- Significance label + triggered criteria
- Notification recipient + CSIRT (from authority registry)
- Deadline: "24h from submission" (NIS2) or "4h" (DORA — determined from `assessment.result_framework` containing "DORA")

### Submit action

1. Validate form (initial assessment text required; support description required if support requested)
2. Build `cyberscale-early-warning` MISP object
3. Add object to existing assessment event in MISP-A via PyMISP `direct_call` to `/objects/add/<event_id>`
4. Add lifecycle tags to the event:
   - `nis2:notification-stage="early-warning"`
   - `cyberscale:notification-status="received"`
   - `cyberscale:support-requested="true"` (if applicable)
5. Record `Submission(target="early_warning", status="success")` with timestamp
6. Redirect to result page with success message

### Result page integration

- "Submit Early Warning" button on result page — visible when early warning recommended AND not yet submitted
- After submission: button replaced by Early Warning Status card (see Section 4)

## 2. MISP Object — `cyberscale-early-warning`

Added to the existing assessment event (not a new event).

### Attributes

| Attribute | MISP type | Description |
|---|---|---|
| `submission-timestamp` | datetime | Auto-generated on submit |
| `deadline` | text | "24h" (NIS2) or "4h" (DORA) |
| `suspected-malicious` | boolean | Entity-confirmed value |
| `cross-border-impact` | boolean | Entity-confirmed value |
| `initial-assessment` | text | Entity free-text description |
| `support-requested` | boolean | Whether entity requests CSIRT assistance |
| `support-description` | text | Nature of support needed (if requested) |
| `notification-recipient` | text | CA or CSIRT abbreviation |

### Template

File: `data/misp-objects/cyberscale-early-warning/definition.json`

```json
{
  "name": "cyberscale-early-warning",
  "meta-category": "misc",
  "description": "CyberScale NIS2 Art. 23(4)(a) early warning notification",
  "version": 1,
  "uuid": "c5e0f001-e27a-4f00-a000-000000000003",
  "attributes": {
    "submission-timestamp": {"misp-attribute": "datetime", "ui-priority": 1},
    "deadline": {"misp-attribute": "text", "ui-priority": 2},
    "suspected-malicious": {"misp-attribute": "boolean", "ui-priority": 3},
    "cross-border-impact": {"misp-attribute": "boolean", "ui-priority": 4},
    "initial-assessment": {"misp-attribute": "text", "ui-priority": 5},
    "support-requested": {"misp-attribute": "boolean", "ui-priority": 6},
    "support-description": {"misp-attribute": "text", "ui-priority": 7},
    "notification-recipient": {"misp-attribute": "text", "ui-priority": 8}
  }
}
```

### Event-level tags added on submission

- `nis2:notification-stage="early-warning"`
- `cyberscale:notification-status="received"`
- `cyberscale:support-requested="true"` (only if support requested)

## 3. Admin Lifecycle Management

Django admin actions on `AssessmentAdmin`. Each action updates MISP-A event tags via PyMISP (remove old status tag, add new one).

### Lifecycle states

| State | Tag value | Who triggers | Meaning |
|---|---|---|---|
| `received` | `cyberscale:notification-status="received"` | Auto on submit | Event landed in MISP-A |
| `acknowledged` | `cyberscale:notification-status="acknowledged"` | Admin action | CA/CSIRT has seen it |
| `under-review` | `cyberscale:notification-status="under-review"` | Admin action | Being evaluated |
| `support-dispatched` | `cyberscale:notification-status="support-dispatched"` | Admin action | CSIRT support sent |
| `closed` | `cyberscale:notification-status="closed"` | Admin action | Early warning phase complete |

### State machine

```
Entity:     Submit
               ↓
            received → acknowledged → under-review → closed
                                          ↓
                                    support-dispatched → closed
```

### Admin actions on AssessmentAdmin

- "Acknowledge early warning" — received → acknowledged
- "Mark under review" — acknowledged → under-review
- "Dispatch support" — under-review → support-dispatched (only if `support-requested` tag exists)
- "Close early warning" — any state → closed

Each action:
1. Validates assessment has `misp_event_uuid` and MISP is configured
2. Reads current tags from MISP-A event
3. Removes old `cyberscale:notification-status` tag
4. Adds new status tag
5. Shows success/error message

### Submission model update

Add `early_warning` to `Submission.TARGET_CHOICES`:

```python
("early_warning", "Early Warning"),
```

## 4. Entity Status Visibility

On the assessment result page, when an early warning has been submitted, a status card appears:

```
Early Warning Status
  Submitted: 2026-04-04 14:30 UTC
  Deadline:  2026-04-05 14:30 UTC (24h)
  Recipient: ILR
  Status:    ACKNOWLEDGED
  CSIRT Support: Requested — DISPATCHED
```

### Implementation

On result page load, if the assessment has a Submission with `target="early_warning"`:
- Query MISP-A via PyMISP for the event's tags (by `misp_event_uuid`)
- Extract `cyberscale:notification-status` value → display as status badge
- Extract `cyberscale:support-requested` → show support line
- Calculate deadline from Submission `submitted_at` timestamp
- If MISP-A is unreachable: show "Status: unavailable" gracefully

### Status badge styling

| Status | Badge class | Color |
|---|---|---|
| received | badge-undetermined | neutral |
| acknowledged | badge-model | blue |
| under-review | badge-model | blue |
| support-dispatched | badge-significant | green |
| closed | badge-not-significant | muted |

## 5. Testing

### Unit tests — `entity/tests/test_early_warning.py`

- Form loads with pre-filled data from assessment
- Form requires initial assessment text
- Form requires support description when support requested
- Submit creates Submission with `target="early_warning"`
- Submit button hidden when not recommended
- Submit button hidden when already submitted
- Form inaccessible for draft assessments
- Status card renders with mock MISP data

### MISP integration tests — extend `entity/tests/test_misp_integration.py`

- Submit adds `cyberscale-early-warning` object to existing assessment event
- Event gets `nis2:notification-stage` and `cyberscale:notification-status` tags
- Support request adds `cyberscale:support-requested` tag
- Admin lifecycle action updates status tag (received → acknowledged)
- Status tag change reflects in subsequent MISP query

## 6. Files Changed

| File | Change |
|---|---|
| `entity/models.py` | Add `early_warning` to Submission TARGET_CHOICES |
| `entity/forms.py` | New `EarlyWarningForm` |
| `entity/views.py` | Add `early_warning_view`, update `assessment_result_view` to query MISP status |
| `entity/urls.py` | Add `/assess/<pk>/early-warning/` |
| `entity/misp_push.py` | Add `add_object_to_event()` helper (PyMISP direct_call to objects/add) |
| `entity/admin.py` | Add lifecycle admin actions (acknowledge, review, dispatch, close) |
| `data/misp-objects/cyberscale-early-warning/definition.json` | New — object template |
| `scripts/misp-init.sh` | Register new template |
| `templates/entity/early_warning_form.html` | New — early warning form |
| `templates/entity/assessment_result.html` | Add submit button + status card |
| `entity/tests/test_early_warning.py` | New — form + view tests |
| `entity/tests/test_misp_integration.py` | Extend with early warning push + lifecycle tests |
