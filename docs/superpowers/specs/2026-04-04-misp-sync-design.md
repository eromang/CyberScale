# MISP-A ↔ MISP-B Sync (v1.4)

## Summary

Add a second MISP instance (MISP-B, authority side) to Docker Compose with full isolation (own MySQL + Redis). Configure bidirectional sync between MISP-A and MISP-B via automated init scripts. Verify with end-to-end tests that events, objects, and tags propagate in both directions.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Goal | Infrastructure + automated sync | No application code changes, pure MISP plumbing |
| MISP-B stack | Full separate (own MySQL + Redis) | Production-like isolation, always running |
| Sync direction | Bidirectional (push A→B + pull B→A) | Avoids rework for v2.0 authority feedback |
| Automation | Three scripts (misp-init, misp-b-init, misp-sync-init) | Clear separation, each does one thing |

## 1. Docker Compose — MISP-B Stack

Three new services added to `docker-compose.yml`:

```yaml
misp-b-db:
  image: mysql:8.0
  # Separate MySQL for MISP-B
  # Volume: misp_b_db_data

misp-b-redis:
  image: redis:7-alpine
  # Separate Redis for MISP-B (password: redispassword)

misp-b:
  image: ghcr.io/misp/misp-docker/misp-core:latest
  # Port: 8444 (vs 8443 for MISP-A)
  # Mounts: data/misp-objects (ro), scripts/misp-b-init.sh (ro)
  # Depends on: misp-b-db, misp-b-redis
```

New volume: `misp_b_db_data`

`cyberscale-web` environment additions:
```yaml
MISP_B_URL: "https://misp-b"
MISP_B_API_KEY: "changeme-run-misp-b-init"
```

Port mapping:
- MISP-A: `8443:443`
- MISP-B: `8444:443`

## 2. Init Scripts

### `scripts/misp-init.sh` (existing, unchanged)

MISP-A setup: templates, API key, lifecycle tags.

### `scripts/misp-b-init.sh` (new)

Same structure as `misp-init.sh`, targeting MISP-B:

1. Wait for MISP-B ready (up to 90s)
2. Disable advanced auth keys (`Security.advanced_authkeys` → false)
3. Generate API key for `admin@admin.test`
4. Copy CyberScale object templates from `/misp-objects/`
5. Register templates via `updateObjectTemplates 1`
6. Create lifecycle tags (same set as MISP-A)
7. Output API key for configuration

### `scripts/misp-sync-init.sh` (new)

Configures bidirectional sync between MISP-A and MISP-B. Requires both instances running with valid admin API keys (passed as arguments or env vars).

Steps:

1. **Create sync user on MISP-A** — `sync@misp-b.local` with Role: Sync user. Generate auth key.
2. **Create sync user on MISP-B** — `sync@misp-a.local` with Role: Sync user. Generate auth key.
3. **Register MISP-B as sync server on MISP-A:**
   - URL: `https://misp-b`
   - Auth key: MISP-B's sync user key
   - Push enabled, pull enabled
   - Self-signed cert accepted
4. **Register MISP-A as sync server on MISP-B:**
   - URL: `https://misp`
   - Auth key: MISP-A's sync user key
   - Push enabled, pull enabled
   - Self-signed cert accepted
5. **Test connection** from both sides via `/servers/testConnection`
6. Output sync status

MISP API calls used:
- `POST /admin/users/add` — create sync user
- `POST /servers/add` — register sync server
- `GET /servers/testConnection/{id}` — verify connectivity

### `scripts/cyberscale.sh` updates

`cmd_start` updated to call init scripts in sequence after all containers are up:

```
1. misp-init.sh      (MISP-A — if API key is placeholder)
2. misp-b-init.sh    (MISP-B — if MISP-B API key is placeholder)
3. misp-sync-init.sh (sync — if not already configured)
```

New commands:
- `cyberscale.sh misp-b-init` — re-init MISP-B
- `cyberscale.sh misp-sync-init` — re-configure sync

## 3. End-to-End Sync Tests

File: `entity/tests/test_misp_sync.py`

Skipped when `MISP_B_URL` and `MISP_B_API_KEY` not set (or placeholder).

### Test 1: Profile push propagates A → B

- Push entity profile event to MISP-A
- Trigger sync: `POST /servers/push/{server_id}` on MISP-A
- Wait briefly for propagation
- Query MISP-B for event by UUID
- Assert event exists with correct info, tags, and profile object attributes

### Test 2: Assessment + early warning propagates A → B

- Push assessment event (with cyberscale-entity-assessment + cyberscale-early-warning objects) to MISP-A
- Trigger sync
- Query MISP-B: verify event exists with both objects and lifecycle tags

### Test 3: Lifecycle tag update propagates A → B

- Push event to MISP-A with `notification-status="received"` tag
- Trigger sync to B (initial)
- Update tag on MISP-A to `"acknowledged"`
- Trigger sync again
- Query MISP-B: verify tag is `"acknowledged"`

### Test 4: B → A feedback

- Create a new event directly on MISP-B (simulating authority classification)
- Trigger sync: `POST /servers/push/{server_id}` on MISP-B
- Query MISP-A: verify event arrived

### Test 5: Custom templates available on MISP-B

- Query MISP-B `/objectTemplates/index`
- Assert `cyberscale-entity-profile`, `cyberscale-entity-assessment`, `cyberscale-early-warning` templates exist and are active

### Sync trigger helper

```python
def trigger_sync(misp, server_id, direction="push"):
    """Force immediate sync instead of waiting for cron."""
    misp.direct_call(f"servers/{direction}/{server_id}/full")
```

### Run command

```bash
docker compose exec \
  -e MISP_URL=https://misp -e MISP_API_KEY=<a-key> \
  -e MISP_B_URL=https://misp-b -e MISP_B_API_KEY=<b-key> \
  cyberscale-web python -m pytest entity/tests/test_misp_sync.py -v
```

## 4. Documentation Updates

### `docs/docker-playground.md`

Update architecture diagram:

```
docker compose up
  │
  ├── cyberscale-web      Port: 8000
  ├── postgres             Port: 5432
  │
  ├── misp (MISP-A)        Port: 8443  ◄──sync──► misp-b (MISP-B)  Port: 8444
  ├── misp-db              MySQL for A              misp-b-db        MySQL for B
  ├── misp-redis           Redis for A              misp-b-redis     Redis for B
```

Add MISP-B section with access details (admin@admin.test, port 8444).

## 5. Files Changed

| File | Change |
|---|---|
| `docker-compose.yml` | Add misp-b, misp-b-db, misp-b-redis + volume + env vars |
| `scripts/misp-b-init.sh` | New — MISP-B setup |
| `scripts/misp-sync-init.sh` | New — bidirectional sync configuration |
| `scripts/cyberscale.sh` | Call all init scripts on start, add misp-b-init and misp-sync-init commands |
| `entity/tests/test_misp_sync.py` | New — 5 E2E sync tests |
| `docs/docker-playground.md` | Update architecture + MISP-B docs |
