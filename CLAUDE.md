# CyberScale

Multi-phase cyber incident severity assessment MCP server.

## Repository structure

```
src/cyberscale/          Core library (inference, tools, national modules)
data/reference/           Reference JSON (ships with package)
data/misp-objects/        Custom MISP object templates (entity-profile, entity-assessment, early-warning)
evaluation/               Benchmarks and validation scripts
docs/                     Design specification, roadmap, lessons learned
scripts/                  Docker management (cyberscale.sh, misp-init.sh)

cyberscale_web/           Django project (settings, urls, wsgi)
entity/                   Django app (models, views, forms, admin, assessment engine, MISP export/push)
entity/authority.py       Authority auto-assignment logic
entity/misp_push.py       PyMISP push + object/tag helpers
entity/misp_export.py     MISP event dict builders
entity/misp_profile_export.py  MISP entity profile builder
entity/management/        Management commands (setup_playground, seed_authorities)
templates/                Django templates (base, entity workflow, early warning)
static/css/               Custom CSS (institutional theme on Pico CSS)
manage.py                 Django management command
Dockerfile                Python 3.11-slim + weasyprint deps
docker-compose.yml        PostgreSQL 16 + Django + MISP + MySQL + Redis
```

Training code is in a separate repo: `github.com/eromang/CyberScale-Training`

## Key architecture

- **Phase 1:** Vulnerability scoring (ML — ModernBERT-base, 62% ceiling)
- **Phase 2:** Contextual severity (ML) + entity significance (deterministic three-tier routing)
- **Phase 3:** Authority classification (fully deterministic — no ML)
- **National:** Luxembourg (ILR per-sector) + Belgium (CCB horizontal) + HCPN crisis qualification

Three-tier routing: IR thresholds (EU-wide) → National thresholds (LU/BE) → NIS2 ML fallback

## Commands

```bash
# Docker playground management
./scripts/cyberscale.sh start      # start all (postgres, MISP, web)
./scripts/cyberscale.sh stop       # ordered shutdown
./scripts/cyberscale.sh test       # run all tests
./scripts/cyberscale.sh status     # docker compose ps
./scripts/cyberscale.sh misp-init  # re-init MISP (templates + API key + tags)
./scripts/cyberscale.sh reset      # destroy volumes, fresh start

# Run tests inside Docker (125 web + 469 core)
docker compose exec cyberscale-web python -m pytest entity/tests/ -v
docker compose exec cyberscale-web python -m pytest src/tests/ -v \
  --ignore=src/tests/test_cwe_enrichment.py \
  --ignore=src/tests/test_generation_balance.py \
  --ignore=src/tests/test_mix_curated.py \
  --ignore=src/tests/test_weighted_loss.py

# MISP integration tests (requires running MISP with valid API key)
docker compose exec -e MISP_URL=https://misp -e MISP_API_KEY=<key> \
  cyberscale-web python -m pytest entity/tests/test_misp_integration.py -v

# Run benchmarks
poetry run python evaluation/benchmark_lu_crisis.py      # HCPN (15 scenarios)
poetry run python evaluation/benchmark_be.py             # Belgium (10 scenarios)
poetry run python evaluation/validate_real_incidents.py   # Real RETEX incidents (10)

# MCP server
poetry run cyberscale
```

## Docker

Claude manages Docker fully — build, up, down, exec, logs, troubleshooting. The user does not run Docker commands.

See `docs/docker-playground.md` for architecture and `docs/product-specification.md` for full product spec.

## Test accounts

- **admin / admin** — superuser + Django admin
- **luxenergy / NIS2Secure2026!** — entity user (LuxPower SA, LU, energy + digital_infrastructure)

## Web playground conventions

- Django project: `cyberscale_web/` — settings, urls, wsgi
- Entity app: `entity/` — models, views, forms, admin, assessment engine, MISP export/push
- Templates: `templates/` — Pico CSS + HTMX, institutional theme via `static/css/cyberscale.css`
- Assessment engine wrapper: `entity/assessment.py` — three-tier routing (IR → national → ML/heuristic), reads CA/CSIRT from EntityType FK
- Authority assignment: `entity/authority.py` — data-driven, sector+MS lookup from `data/reference/authorities.json`
- MISP push: `entity/misp_push.py` — `push_event()`, `add_object_to_event()`, `update_event_tags()`, `get_event_tags()`
- MISP object templates: `data/misp-objects/` — entity-profile, entity-assessment, early-warning
- Enums/choices in forms loaded from `data/reference/nis2_entity_types.json` — not hardcoded
- Authority/CSIRT data loaded from `data/reference/authorities.json` — not hardcoded
- HTMX endpoint for sector → entity type filtering: `/htmx/entity-types/`
- Early warning lifecycle: MISP tags are source of truth, admin actions update tags via PyMISP

## Conventions

- National modules: `src/cyberscale/national/{ms}.py` + `data/reference/{ms}_thresholds.json` + registry entry
- All valid enums loaded from reference JSON via `src/cyberscale/config.py` — do not hardcode
- Logging via `logging.getLogger("cyberscale.*")` at decision points
- Phase 3 is deterministic — do not add ML models to it
- HCPN crisis qualification scopes to **impact on Luxembourg**, not entity establishment
- Delegated thresholds return "undetermined" — never invent values
- CIRCL is one of Luxembourg's CSIRTs (alongside GOVCERT.LU), not the primary
