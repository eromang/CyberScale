#!/bin/bash
# CyberScale MISP initialization script.
# Runs inside the MISP container to:
#   1. Wait for MISP to be ready
#   2. Disable advanced auth keys
#   3. Generate API key for admin user
#   4. Copy and register custom object templates
#   5. Output the API key for cyberscale-web configuration
#
# Usage: docker compose exec misp /scripts/misp-init.sh

set -e

CAKE="/var/www/MISP/app/Console/cake"
OBJECTS_DIR="/var/www/MISP/app/files/misp-objects/objects"
CUSTOM_DIR="/misp-objects"

echo "CyberScale MISP initialization"
echo "==============================="

# Wait for MISP web to be ready
echo "[1/5] Waiting for MISP to be ready..."
for i in $(seq 1 60); do
    if $CAKE admin getSetting MISP.baseurl >/dev/null 2>&1; then
        echo "  MISP is ready."
        break
    fi
    if [ $i -eq 60 ]; then
        echo "  ERROR: MISP did not become ready within 60 seconds."
        exit 1
    fi
    sleep 2
done

# Disable advanced auth keys (simple keys are easier for automation)
echo "[2/5] Configuring authentication..."
$CAKE admin setSetting Security.advanced_authkeys false >/dev/null 2>&1 || true

# Get or generate API key
echo "[3/5] Configuring API key..."
if [ -n "$ADMIN_KEY" ] && [ ${#ADMIN_KEY} -eq 40 ]; then
    API_KEY="$ADMIN_KEY"
    echo "  Using fixed ADMIN_KEY from environment"
else
    KEY_OUTPUT=$($CAKE user change_authkey admin@admin.test 2>&1)
    API_KEY=$(echo "$KEY_OUTPUT" | sed -n 's/.*\(key created: \|changed to: \)\(.*\)/\2/p')
    if [ -z "$API_KEY" ]; then
        echo "  ERROR: Failed to generate API key."
        echo "  Output: $KEY_OUTPUT"
        exit 1
    fi
fi
echo "  API key: $API_KEY"

# Copy custom object templates
echo "[4/5] Installing CyberScale object templates..."
if [ -d "$CUSTOM_DIR" ]; then
    for template_dir in "$CUSTOM_DIR"/cyberscale-*/; do
        template_name=$(basename "$template_dir")
        if [ -f "$template_dir/definition.json" ]; then
            mkdir -p "$OBJECTS_DIR/$template_name"
            cp "$template_dir/definition.json" "$OBJECTS_DIR/$template_name/"
            chown -R www-data:www-data "$OBJECTS_DIR/$template_name"
            echo "  Installed: $template_name"
        fi
    done

    # Register templates in MISP database
    UPDATED=$($CAKE admin updateObjectTemplates 1 2>&1)
    echo "  $UPDATED"
else
    echo "  WARNING: $CUSTOM_DIR not found. Mount data/misp-objects/ to /misp-objects/."
fi

# Create lifecycle tags
echo "[5/6] Creating lifecycle tags..."
TAGS=(
    'cyberscale:notification-status="received"'
    'cyberscale:notification-status="acknowledged"'
    'cyberscale:notification-status="under-review"'
    'cyberscale:notification-status="support-dispatched"'
    'cyberscale:notification-status="closed"'
    'nis2:notification-stage="early-warning"'
    'cyberscale:support-requested="true"'
)
for TAG in "${TAGS[@]}"; do
    curl -sk "https://localhost/tags/add" \
        -H "Authorization: $API_KEY" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "{\"Tag\":{\"name\":\"$TAG\",\"colour\":\"#0088cc\"}}" > /dev/null 2>&1
done
echo "  Created ${#TAGS[@]} lifecycle tags"

# Output configuration
echo "[6/6] Done."
echo ""
echo "==============================="
echo "MISP API Key: $API_KEY"
echo ""
echo "Update cyberscale-web environment:"
echo "  MISP_URL=https://misp"
echo "  MISP_API_KEY=$API_KEY"
echo "  MISP_SSL_VERIFY=false"
echo "==============================="
