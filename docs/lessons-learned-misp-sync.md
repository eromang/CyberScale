# Lessons Learned: MISP Synchronisation

Based on debugging CyberScale v1.4 and studying the official [MISP synchronisation repo](https://github.com/MISP/misp-synchronisation).

## Critical Findings

### 1. HTTP between containers, not HTTPS

The official MISP sync repo uses **HTTP** (`http://misp_${target}`) for inter-container communication. HTTPS with self-signed certificates causes the CakePHP HTTP client to fail on push operations (`/events/add/metadata:1` returns 403/500).

**Fix:** Use `DISABLE_SSL_REDIRECT=true` in MISP Docker env, enable the MISP nginx include on port 80, and configure sync servers with `http://` URLs.

### 2. Shared Redis with per-instance database numbers

The official repo uses a **single Redis** instance shared by all MISP containers, with unique `redis_database` per instance:

```bash
cake Admin setSetting 'MISP.redis_database' $((NUM_INSTANCES + id))
cake Admin setSetting 'SimpleBackgroundJobs.redis_database' $id
```

Our approach (separate Redis per MISP) works but misses this key detail — workers and caching share the Redis and can interfere without separate DB numbers.

### 3. Organisation setup is critical

The sync flow requires:
1. **Generate unique UUIDs** for each org
2. **Create ALL orgs on ALL instances** (each instance knows about every org)
3. **Set host org** per instance (`MISP.host_org_id`)
4. **Create org admin users** per instance (not just the default admin)

Our mistake: we only created the remote org on the target instance, not on all instances. The official approach creates every org everywhere.

### 4. Auth keys via `/auth_keys/add`, not `change_authkey`

The official repo uses:
```bash
curl -X POST "http://host/auth_keys/add/${user_id}" \
  -d '{"user_id": "...", "comment": "Sync key"}'
```

This returns `authkey_raw` in the response. The `cake user change_authkey` command works differently and can interfere with advanced auth key settings.

### 5. Sync user setup

Sync users must have:
- `role_id: 5` (Sync user role)
- `change_pw: false` (no password change required)
- `org_id`: **the source org's ID on the target instance** (not the target's own org)
- An explicitly created auth key via `/auth_keys/add`

### 6. Publishing with `disable_background_processing:1`

The official test helper publishes events with:
```python
events/publish/{event_id}/disable_background_processing:1
```

This **bypasses the background job queue** and publishes immediately. Without this, publish goes to the worker queue which may be delayed or broken.

Our `misp.publish(event_id)` uses the default background processing, which explains why events weren't always published when expected.

### 7. `DISABLE_SSL_REDIRECT=true`

The official repo sets this in the `.env` file:
```bash
sed 's/^# *\(DISABLE_SSL_REDIRECT=true\)/\1/' .env > "$TMP_ENV"
```

This tells the MISP Docker entrypoint to not configure the HTTP→HTTPS redirect in nginx. Without this, port 80 redirects to 443 and inter-container HTTP fails.

### 8. Docker Compose restarts after configuration

The official script **stops and restarts** all containers after configuration:
```bash
$COMPOSE_CMD down
sleep 5
$COMPOSE_CMD up -d
```

This ensures all MISP instances pick up the configuration changes (Redis settings, org changes, etc.).

### 9. `config.php` permission issues

The MISP Docker image sometimes creates `/var/www/MISP/app/Config/config.php` with restrictive permissions (`-rw------- root`). The PHP-FPM process (running as `www-data`) can't read it, causing 500 errors on all web requests while the CLI (running as root) works fine.

**Fix:** `chmod 644 /var/www/MISP/app/Config/config.php` after any configuration change, or ensure the file is owned by `www-data`.

### 10. MariaDB vs MySQL

The official repo uses **MariaDB 10.11** instead of MySQL 8.0. While functionally similar, this may affect compatibility with some MISP features.

## Action Items for CyberScale v1.4

1. Switch to HTTP between MISP containers (add `DISABLE_SSL_REDIRECT=true`)
2. Use single shared Redis with per-instance DB numbers (or keep separate Redis but set DB numbers)
3. Create all orgs on all instances before setting up sync
4. Set `MISP.host_org_id` on each instance
5. Use `disable_background_processing:1` for publish in push_event()
6. Add `chmod 644` for config.php in init scripts
7. Restart containers after sync configuration
8. Consider using the official misp-synchronisation repo's INSTALL.sh as a reference for our `misp-sync-init.sh`
