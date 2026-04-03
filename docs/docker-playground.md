# CyberScale — Docker Playground Setup

Local development and testing environment using Docker Compose.

---

## Prerequisites

- Docker Desktop (Mac/Windows) or Docker Engine + Docker Compose (Linux)
- Git
- ~4GB disk space (ML models + MISP if enabled)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/eromang/CyberScale.git
cd CyberScale

# Start the playground
docker compose up -d

# Access the web interface
open http://localhost:8000
```

---

## Architecture

```
docker compose up
  │
  ├── cyberscale-web     (Django + HTMX + CyberScale core)
  │   Port: 8000
  │   - Entity web form (Art. 27 registration + profile editing)
  │   - Assessment engine (Phase 1 + 2)
  │   - PDF / MISP JSON export
  │   - Admin MISP push (profile + assessment)
  │   - Django admin (/admin)
  │
  ├── postgres            (PostgreSQL 16)
  │   Port: 5432
  │   - Entity profiles (Art. 27 fields)
  │   - Assessment history
  │   - Submission records
  │
  ├── misp               (MISP-A instance)
  │   Port: 8443
  │   - Entity profiles as cyberscale-entity-profile objects
  │   - Assessment events as cyberscale-entity-assessment objects
  │   - Custom object templates auto-registered
  │
  ├── misp-db            (MySQL 8)
  │   - MISP backend database
  │
  └── misp-redis         (Redis 7)
      - MISP session/cache store
```

---

## Docker Compose Configuration

The actual configuration files are at the repo root — see `docker-compose.yml` and `Dockerfile` directly. The MCP server service (`cyberscale-mcp`) is not yet wired into compose; it will be added when MCP integration is implemented.

Key details:
- **PostgreSQL 16-alpine** with healthcheck, data persisted in `postgres_data` volume
- **cyberscale-web** runs migrations + collectstatic + runserver on startup
- **WeasyPrint** system deps (Pango, GdkPixbuf) installed in Dockerfile
- **Source mounted** as `/app` for live reload during development
- **Model cache** volume at `/app/data/models` (ML models not included in image)

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `SECRET_KEY` | (required) | Django secret key |
| `DEBUG` | `false` | Django debug mode |
| `ALLOWED_HOSTS` | `localhost` | Comma-separated allowed hosts |
| `MISP_URL` | `https://misp` | MISP-A instance URL |
| `MISP_API_KEY` | (set after init) | MISP API key (from `misp-init.sh`) |
| `MISP_SSL_VERIFY` | `false` | Verify MISP SSL certificate (false for self-signed) |
| `CYBERSCALE_MODEL_PATH` | `data/models` | Path to ML model weights |

---

## First Run

### 1. Start services

```bash
docker compose up -d
```

On first start, `setup_playground` runs automatically: creates admin superuser (admin/admin) and a default entity.

### 2. Initialize MISP

MISP takes ~30 seconds to fully start. Then run:

```bash
docker compose exec misp /scripts/misp-init.sh
```

This will:
- Register CyberScale custom object templates (`cyberscale-entity-profile`, `cyberscale-entity-assessment`)
- Generate a MISP API key
- Output the key for configuration

### 3. Configure MISP API key

Copy the API key from the init script output and update `docker-compose.yml`:

```yaml
MISP_API_KEY: "<paste-key-here>"
```

Then restart:

```bash
docker compose up -d cyberscale-web
```

### 4. Access the application

| URL | Purpose |
|---|---|
| http://localhost:8000 | Entity dashboard (login: admin/admin) |
| http://localhost:8000/register | Register a new entity |
| http://localhost:8000/profile/edit/ | Edit entity profile (Art. 27 fields) |
| http://localhost:8000/admin | Django admin (MISP push actions) |
| https://localhost:8443 | MISP web interface (admin@admin.test / admin) |

### 5. Entity workflow

1. **Register** at `/register` — org name, sector, entity type, MS
2. **Edit profile** at `/profile/edit/` — Art. 27 fields (address, contacts, IP ranges, MS services)
3. **Run assessment** at `/assess/` — describe incident, per-type impacts
4. **View results** — significance, early warning, triggered criteria
5. **Export** — PDF download, MISP JSON download

### 6. Admin MISP push workflow

In Django admin (`/admin`):

1. **Push profile first:** Entities → select entity → "Push profile to MISP"
2. **Push assessment:** Assessments → select assessment → "Push to MISP" (requires profile pushed first)
3. **Verify in MISP:** Open https://localhost:8443 to see events with objects

---

## MISP Instance

MISP is included in docker-compose.yml (MISP-A in the four-tier architecture). It runs alongside cyberscale-web with MySQL and Redis backends.

### Custom Object Templates

CyberScale registers two custom MISP object templates (stored in `data/misp-objects/`):

| Template | UUID | Purpose |
|---|---|---|
| `cyberscale-entity-profile` | `c5e0f001-...-01` | Art. 27 entity registration data |
| `cyberscale-entity-assessment` | `c5e0f001-...-02` | NIS2 incident severity assessment |

Templates are installed by `scripts/misp-init.sh` and registered via `updateObjectTemplates`.

### Re-initializing MISP

If MISP data is lost (volume removed), re-run:

```bash
docker compose exec misp /scripts/misp-init.sh
# Copy API key to docker-compose.yml
docker compose up -d cyberscale-web
```

---

## ML Models

ML models (Phase 1 scorer + Phase 2 contextual) are NOT included in the Docker image — they're too large.

### Option A: Download from HuggingFace (recommended)

```bash
docker compose exec cyberscale-web python -c "
from huggingface_hub import snapshot_download
snapshot_download('eromang/cyberscale-scorer-v6', local_dir='data/models/scorer')
snapshot_download('eromang/cyberscale-contextual-v4', local_dir='data/models/contextual')
"
```

### Option B: Mount from host

If you have models locally:
```yaml
# In docker-compose.yml, add to cyberscale-web volumes:
volumes:
  - ./data/models:/app/data/models
```

### Option C: Run without ML models

The deterministic components (national thresholds, HCPN crisis qualification, Phase 3 classification) work without ML models. Phase 1 and Phase 2 qualitative assessment will return errors until models are deployed.

---

## Development Workflow

### Run tests inside container

```bash
# Core library tests (469+)
docker compose exec cyberscale-web python -m pytest src/tests/ -v \
  --ignore=src/tests/test_cwe_enrichment.py \
  --ignore=src/tests/test_generation_balance.py \
  --ignore=src/tests/test_mix_curated.py \
  --ignore=src/tests/test_weighted_loss.py

# Web app tests (62+)
docker compose exec cyberscale-web python -m pytest entity/tests/ -v

# MISP integration tests (requires configured MISP)
docker compose exec \
  -e MISP_URL=https://misp \
  -e MISP_API_KEY=<your-key> \
  cyberscale-web python -m pytest entity/tests/test_misp_integration.py -v
```

### Run benchmarks

```bash
docker compose exec cyberscale-web python evaluation/benchmark_lu_crisis.py
docker compose exec cyberscale-web python evaluation/benchmark_be.py
docker compose exec cyberscale-web python evaluation/validate_real_incidents.py
```

### Django shell

```bash
docker compose exec cyberscale-web python manage.py shell
```

### View logs

```bash
docker compose logs -f cyberscale-web
```

### Reset database

```bash
docker compose down -v  # removes volumes
docker compose up -d    # fresh start
```

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError: cyberscale` | Run `pip install -e .` inside container |
| PDF generation fails | Ensure weasyprint system deps are installed (Pango, GdkPixbuf) |
| MISP push fails with SSL error | Set `MISP_SSL_VERIFY=false` in docker-compose.yml |
| MISP objects empty after push | Run `misp-init.sh` to register custom templates |
| MISP 500 errors | MISP still initializing — wait 30s and retry |
| Models not found | Download from HuggingFace or mount from host (see ML Models section) |
| Port 8000 in use | Change port mapping in docker-compose.yml: `"8080:8000"` |
| Database connection refused | Wait for PostgreSQL healthcheck: `docker compose ps` should show "healthy" |
