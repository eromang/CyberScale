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
  │   - Entity web form
  │   - Assessment engine
  │   - PDF generation
  │   - REST API
  │   - Django admin (/admin)
  │
  ├── cyberscale-mcp     (FastMCP server)
  │   Port: 8001
  │   - MCP JSON-RPC endpoint
  │   - For AI tool integration (Claude, Copilot)
  │
  ├── postgres            (PostgreSQL 16)
  │   Port: 5432
  │   - Entity profiles
  │   - Assessment history
  │   - Submission records
  │
  └── misp (optional)     (MISP instance)
      Port: 8443
      - Local MISP for testing push/export
      - Pre-configured with CyberScale taxonomies
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
| `MISP_URL` | (empty) | MISP instance URL (optional) |
| `MISP_API_KEY` | (empty) | MISP API key (optional) |
| `MISP_VERIFY_SSL` | `true` | Verify MISP SSL certificate |
| `MISP_DEFAULT_TLP` | `tlp:amber` | Default TLP for entity assessments |
| `CYBERSCALE_MODEL_PATH` | `data/models` | Path to ML model weights |

---

## First Run

### 1. Start services

```bash
docker compose up -d
```

### 2. Create admin user

```bash
docker compose exec cyberscale-web python manage.py createsuperuser
```

### 3. Access the application

| URL | Purpose |
|---|---|
| http://localhost:8000 | Entity web form |
| http://localhost:8000/admin | Django admin (manage entities, view assessments) |
| http://localhost:8001 | MCP server (for AI tool integration) |

### 4. Register a test entity

Via Django admin (http://localhost:8000/admin):
- Create a new entity profile
- Sector: energy
- Entity type: electricity_undertaking
- MS established: LU

Or via the registration page at http://localhost:8000/register.

### 5. Create a test assessment

Navigate to http://localhost:8000 and fill in the form:
- Description: "SCADA system compromise at electricity provider"
- Service impact: unavailable
- Duration: 3 hours
- Suspected malicious: yes

The result page shows significance determination, triggered criteria, and early warning recommendation.

### 6. Export results

- **PDF:** Click "Download PDF" on the result page
- **MISP JSON:** Click "Download MISP JSON"
- **Push to MISP:** Click "Submit to CSIRT" (requires MISP configuration)

---

## Optional: Local MISP Instance

For testing MISP push/export without a remote instance.

### `docker-compose.misp.yml` (override)

```yaml
services:
  misp:
    image: ghcr.io/misp/misp-docker/misp-core:latest
    environment:
      MISP_BASEURL: https://localhost:8443
      MISP_ADMIN_EMAIL: admin@cyberscale.local
      MISP_ADMIN_PASSPHRASE: admin_password_change_me
    ports:
      - "8443:443"
    volumes:
      - misp_data:/var/www/MISP/app/files

  misp-db:
    image: mariadb:11
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: misp_dev
      MYSQL_ROOT_PASSWORD: misp_root_dev
    volumes:
      - misp_db_data:/var/lib/mysql

volumes:
  misp_data:
  misp_db_data:
```

### Start with MISP

```bash
docker compose -f docker-compose.yml -f docker-compose.misp.yml up -d
```

### Configure CyberScale → MISP connection

1. Access MISP at https://localhost:8443 (accept self-signed cert)
2. Log in with `admin@cyberscale.local` / `admin_password_change_me`
3. Go to Administration → Auth Keys → Add Authentication Key
4. Copy the API key
5. Set in `.env`:
   ```
   MISP_URL=https://misp:8443
   MISP_API_KEY=<your-key>
   MISP_VERIFY_SSL=false
   ```
6. Restart: `docker compose restart cyberscale-web`

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
docker compose exec cyberscale-web python -m pytest src/tests/ -v
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
| MISP push fails with SSL error | Set `MISP_VERIFY_SSL=false` for local MISP |
| Models not found | Download from HuggingFace or mount from host (see ML Models section) |
| Port 8000 in use | Change port mapping in docker-compose.yml: `"8080:8000"` |
| Database connection refused | Wait for PostgreSQL healthcheck: `docker compose ps` should show "healthy" |
