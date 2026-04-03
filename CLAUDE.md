# CyberScale

Multi-phase cyber incident severity assessment MCP server.

## Repository structure

```
src/cyberscale/          Core library (inference, tools, national modules)
data/reference/           Reference JSON (ships with package)
evaluation/               Benchmarks and validation scripts
docs/                     Design specification, roadmap, lessons learned
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
# Run tests (485+)
poetry run python -m pytest src/tests/ -v

# Run benchmarks
poetry run python evaluation/benchmark_lu_crisis.py      # HCPN (15 scenarios)
poetry run python evaluation/benchmark_be.py             # Belgium (10 scenarios)
poetry run python evaluation/validate_real_incidents.py   # Real RETEX incidents (10)

# E2E demos
poetry run python evaluation/e2e_v8_full_demo.py         # Full pipeline
poetry run python evaluation/e2e_be_demo.py              # Belgium
poetry run python evaluation/e2e_v8_demo.py              # HCPN scenarios

# MCP server
poetry run cyberscale
```

## Docker

Claude manages Docker fully — build, up, down, exec, logs, troubleshooting. The user does not run Docker commands.

See `docs/docker-playground.md` for architecture and `docs/product-specification.md` for full product spec.

## Conventions

- National modules: `src/cyberscale/national/{ms}.py` + `data/reference/{ms}_thresholds.json` + registry entry
- All valid enums loaded from reference JSON via `src/cyberscale/config.py` — do not hardcode
- Logging via `logging.getLogger("cyberscale.*")` at decision points
- Phase 3 is deterministic — do not add ML models to it
- HCPN crisis qualification scopes to **impact on Luxembourg**, not entity establishment
- Delegated thresholds return "undetermined" — never invent values
- CIRCL is one of Luxembourg's CSIRTs (alongside GOVCERT.LU), not the primary
