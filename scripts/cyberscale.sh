#!/bin/bash
# CyberScale Docker playground management script.
#
# Usage:
#   ./scripts/cyberscale.sh start          Start all services (first run includes MISP init)
#   ./scripts/cyberscale.sh stop           Stop all services
#   ./scripts/cyberscale.sh restart        Restart all services
#   ./scripts/cyberscale.sh status         Show service status
#   ./scripts/cyberscale.sh logs           Follow logs (all services)
#   ./scripts/cyberscale.sh test           Run all tests
#   ./scripts/cyberscale.sh reset          Stop, remove volumes, fresh start
#   ./scripts/cyberscale.sh misp-init      Re-initialize MISP-A (templates + API key)
#   ./scripts/cyberscale.sh misp-b-init    Re-initialize MISP-B
#   ./scripts/cyberscale.sh misp-sync-init Configure sync between MISP-A and MISP-B
#   ./scripts/cyberscale.sh build          Rebuild cyberscale-web image

set -e

cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[cyberscale]${NC} $1"; }
ok()   { echo -e "${GREEN}[cyberscale]${NC} $1"; }
warn() { echo -e "${YELLOW}[cyberscale]${NC} $1"; }
err()  { echo -e "${RED}[cyberscale]${NC} $1"; }

wait_for_misp() {
    log "Waiting for MISP-A to be ready (up to 90s)..."
    for i in $(seq 1 45); do
        if docker compose exec -T misp /var/www/MISP/app/Console/cake admin getSetting MISP.baseurl >/dev/null 2>&1; then
            ok "MISP-A is ready."
            return 0
        fi
        sleep 2
    done
    warn "MISP-A did not become ready within 90 seconds."
    return 1
}

wait_for_misp_b() {
    log "Waiting for MISP-B to be ready (up to 90s)..."
    for i in $(seq 1 45); do
        if docker compose exec -T misp-b /var/www/MISP/app/Console/cake admin getSetting MISP.baseurl >/dev/null 2>&1; then
            ok "MISP-B is ready."
            return 0
        fi
        sleep 2
    done
    warn "MISP-B did not become ready within 90 seconds."
    return 1
}

misp_init() {
    if wait_for_misp; then
        log "Initializing MISP-A (templates + API key)..."
        docker compose exec -T misp /scripts/misp-init.sh
        echo ""
        warn "If the API key changed, update MISP_API_KEY in docker-compose.yml and run:"
        warn "  docker compose up -d cyberscale-web"
    fi
}

misp_b_init() {
    if wait_for_misp_b; then
        log "Initializing MISP-B (templates + API key)..."
        docker compose exec -T misp-b /scripts/misp-b-init.sh
        echo ""
        warn "If the API key changed, update MISP_B_API_KEY in docker-compose.yml and run:"
        warn "  docker compose up -d cyberscale-web"
    fi
}

cmd_start() {
    log "Building images..."
    docker compose build --quiet

    log "Starting databases (postgres, misp-db, misp-redis, misp-b-db, misp-b-redis)..."
    docker compose up -d postgres misp-db misp-redis misp-b-db misp-b-redis

    log "Waiting for databases to be healthy..."
    docker compose up -d --wait postgres misp-db misp-redis misp-b-db misp-b-redis 2>/dev/null || sleep 10

    log "Starting MISP-A and MISP-B..."
    docker compose up -d misp misp-b

    log "Starting CyberScale web..."
    docker compose up -d cyberscale-web

    # Check if MISP-A needs initialization
    MISP_KEY=$(grep 'MISP_API_KEY:' docker-compose.yml | head -1 | sed 's/.*: *"//' | sed 's/".*//')
    if [ "$MISP_KEY" = "changeme-run-misp-authkey-setup" ] || [ -z "$MISP_KEY" ]; then
        log "First run detected — initializing MISP-A..."
        misp_init
    else
        ok "MISP-A API key already configured."
    fi

    # Check if MISP-B needs initialization
    MISP_B_KEY=$(grep 'MISP_B_API_KEY:' docker-compose.yml | head -1 | sed 's/.*: *"//' | sed 's/".*//')
    if [ "$MISP_B_KEY" = "changeme-run-misp-b-init" ] || [ -z "$MISP_B_KEY" ]; then
        log "Initializing MISP-B..."
        misp_b_init
    else
        ok "MISP-B API key already configured."
    fi

    echo ""
    ok "CyberScale is running!"
    echo ""
    echo "  Web:      http://localhost:8000        (admin/admin)"
    echo "  Admin:    http://localhost:8000/admin"
    echo "  MISP-A:   https://localhost:8443       (admin@admin.test/admin)"
    echo "  MISP-B:   https://localhost:8444       (admin@admin.test/admin)"
    echo ""
}

cmd_stop() {
    log "Stopping all services..."
    docker compose stop cyberscale-web
    docker compose stop misp misp-b
    docker compose stop misp-redis misp-db misp-b-redis misp-b-db
    docker compose stop postgres
    ok "All services stopped."
}

cmd_restart() {
    cmd_stop
    echo ""
    log "Starting services..."
    docker compose up -d postgres misp-db misp-redis misp-b-db misp-b-redis
    docker compose up -d --wait postgres misp-db misp-redis misp-b-db misp-b-redis 2>/dev/null || sleep 10
    docker compose up -d misp misp-b
    docker compose up -d cyberscale-web
    ok "All services restarted."
    echo ""
    echo "  Web:      http://localhost:8000"
    echo "  MISP-A:   https://localhost:8443"
    echo "  MISP-B:   https://localhost:8444"
    echo ""
}

cmd_status() {
    docker compose ps
}

cmd_logs() {
    docker compose logs -f "$@"
}

cmd_test() {
    log "Running web app tests..."
    docker compose exec cyberscale-web python -m pytest entity/tests/ -v \
        --ignore=entity/tests/test_misp_integration.py \
        --ignore=entity/tests/test_misp_sync.py

    echo ""
    log "Running core library tests..."
    docker compose exec cyberscale-web python -m pytest src/tests/ -v \
        --ignore=src/tests/test_cwe_enrichment.py \
        --ignore=src/tests/test_generation_balance.py \
        --ignore=src/tests/test_mix_curated.py \
        --ignore=src/tests/test_weighted_loss.py

    echo ""
    ok "All tests complete."
}

cmd_reset() {
    warn "This will destroy all data (database, MISP-A, MISP-B, volumes)."
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Stopping and removing everything..."
        docker compose down -v
        ok "Volumes removed. Run './scripts/cyberscale.sh start' for a fresh start."
    else
        log "Aborted."
    fi
}

cmd_misp_init() {
    misp_init
}

cmd_misp_b_init() {
    misp_b_init
}

cmd_misp_sync_init() {
    MISP_KEY=$(grep 'MISP_API_KEY:' docker-compose.yml | head -1 | sed 's/.*: *"//' | sed 's/".*//')
    MISP_B_KEY=$(grep 'MISP_B_API_KEY:' docker-compose.yml | head -1 | sed 's/.*: *"//' | sed 's/".*//')
    ./scripts/misp-sync-init.sh "$MISP_KEY" "$MISP_B_KEY"
}

cmd_build() {
    log "Rebuilding cyberscale-web image..."
    docker compose build cyberscale-web
    ok "Image rebuilt. Run './scripts/cyberscale.sh restart' to apply."
}

case "${1:-}" in
    start)          cmd_start ;;
    stop)           cmd_stop ;;
    restart)        cmd_restart ;;
    status)         cmd_status ;;
    logs)           shift; cmd_logs "$@" ;;
    test)           cmd_test ;;
    reset)          cmd_reset ;;
    misp-init)      cmd_misp_init ;;
    misp-b-init)    cmd_misp_b_init ;;
    misp-sync-init) cmd_misp_sync_init ;;
    build)          cmd_build ;;
    *)
        echo "CyberScale Docker Playground"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start          Start all services (first run includes MISP init)"
        echo "  stop           Stop all services (ordered shutdown)"
        echo "  restart        Restart all services"
        echo "  status         Show service status"
        echo "  logs           Follow logs (optionally: logs cyberscale-web)"
        echo "  test           Run all tests (web + core)"
        echo "  reset          Stop, remove volumes, fresh start"
        echo "  misp-init      Re-initialize MISP-A (templates + API key)"
        echo "  misp-b-init    Re-initialize MISP-B"
        echo "  misp-sync-init Configure sync between MISP-A and MISP-B"
        echo "  build          Rebuild cyberscale-web image"
        exit 1
        ;;
esac
