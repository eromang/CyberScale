#!/bin/bash
# Configure bidirectional sync between MISP-A and MISP-B.
# Runs from the host (not inside a container) — uses docker compose exec.
#
# Requires: both MISP instances initialized (misp-init.sh + misp-b-init.sh done)
#
# Usage: ./scripts/misp-sync-init.sh <MISP_A_KEY> <MISP_B_KEY>

set -e

cd "$(dirname "$0")/.."

MISP_A_KEY="${1:-}"
MISP_B_KEY="${2:-}"

if [ -z "$MISP_A_KEY" ] || [ -z "$MISP_B_KEY" ]; then
    echo "Usage: $0 <MISP_A_API_KEY> <MISP_B_API_KEY>"
    echo ""
    echo "Run misp-init.sh and misp-b-init.sh first to get the keys."
    exit 1
fi

echo "CyberScale MISP Sync Configuration"
echo "===================================="

# Step 1: Create sync user on MISP-A (for MISP-B to authenticate against A)
echo "[1/5] Creating sync user on MISP-A..."
SYNC_A_KEY=$(docker compose exec -T cyberscale-web python -c "
from pymisp import PyMISP
import warnings, json, sys
warnings.filterwarnings('ignore')
misp = PyMISP('https://misp', '${MISP_A_KEY}', ssl=False, timeout=30)

users = misp.direct_call('admin/users/index')
user_list = users if isinstance(users, list) else []
sync_user = next((u.get('User', u) for u in user_list if u.get('User', u).get('email') == 'sync@misp-b.local'), None)

if sync_user:
    result = misp.direct_call(f'users/change_authkey/{sync_user[\"id\"]}')
    if isinstance(result, dict) and 'AuthKey' in result:
        print(result['AuthKey']['authkey'])
    else:
        print('')
else:
    user_data = {'email': 'sync@misp-b.local', 'org_id': 1, 'role_id': 5, 'password': 'SyncP4ssw0rd!Aa', 'change_pw': 0, 'termsaccepted': 1}
    result = misp.direct_call('admin/users/add', {'User': user_data})
    if isinstance(result, dict) and 'User' in result:
        uid = result['User']['id']
        key_result = misp.direct_call(f'users/change_authkey/{uid}')
        if isinstance(key_result, dict) and 'AuthKey' in key_result:
            print(key_result['AuthKey']['authkey'])
        else:
            print('')
    else:
        print('', file=sys.stderr)
        print(json.dumps(result)[:200], file=sys.stderr)
        print('')
" 2>&1 | grep -E '^[a-zA-Z0-9]{40}$' | head -1)

if [ -z "$SYNC_A_KEY" ]; then
    echo "  ERROR: Failed to create sync user on MISP-A"
    exit 1
fi
echo "  Sync user key (A): ${SYNC_A_KEY:0:10}..."

# Step 2: Create sync user on MISP-B (for MISP-A to authenticate against B)
echo "[2/5] Creating sync user on MISP-B..."
SYNC_B_KEY=$(docker compose exec -T cyberscale-web python -c "
from pymisp import PyMISP
import warnings, json, sys
warnings.filterwarnings('ignore')
misp = PyMISP('https://misp-b', '${MISP_B_KEY}', ssl=False, timeout=30)

users = misp.direct_call('admin/users/index')
user_list = users if isinstance(users, list) else []
sync_user = next((u.get('User', u) for u in user_list if u.get('User', u).get('email') == 'sync@misp-a.local'), None)

if sync_user:
    result = misp.direct_call(f'users/change_authkey/{sync_user[\"id\"]}')
    if isinstance(result, dict) and 'AuthKey' in result:
        print(result['AuthKey']['authkey'])
    else:
        print('')
else:
    user_data = {'email': 'sync@misp-a.local', 'org_id': 1, 'role_id': 5, 'password': 'SyncP4ssw0rd!Aa', 'change_pw': 0, 'termsaccepted': 1}
    result = misp.direct_call('admin/users/add', {'User': user_data})
    if isinstance(result, dict) and 'User' in result:
        uid = result['User']['id']
        key_result = misp.direct_call(f'users/change_authkey/{uid}')
        if isinstance(key_result, dict) and 'AuthKey' in key_result:
            print(key_result['AuthKey']['authkey'])
        else:
            print('')
    else:
        print('', file=sys.stderr)
        print(json.dumps(result)[:200], file=sys.stderr)
        print('')
" 2>&1 | grep -E '^[a-zA-Z0-9]{40}$' | head -1)

if [ -z "$SYNC_B_KEY" ]; then
    echo "  ERROR: Failed to create sync user on MISP-B"
    exit 1
fi
echo "  Sync user key (B): ${SYNC_B_KEY:0:10}..."

# Step 3: Register MISP-B as sync server on MISP-A
echo "[3/5] Registering MISP-B on MISP-A..."
docker compose exec -T cyberscale-web python -c "
from pymisp import PyMISP
import warnings, json
warnings.filterwarnings('ignore')
misp = PyMISP('https://misp', '${MISP_A_KEY}', ssl=False, timeout=30)

servers = misp.direct_call('servers/index')
server_list = servers if isinstance(servers, list) else []
b_exists = any(s.get('Server', s).get('url') == 'https://misp-b' for s in server_list)

if b_exists:
    print('Already registered')
else:
    server_data = {'Server': {'url': 'https://misp-b', 'authkey': '${SYNC_B_KEY}', 'name': 'MISP-B (Authority)', 'remote_org_id': 1, 'push': True, 'pull': True, 'self_signed': True, 'caching_enabled': False}}
    result = misp.direct_call('servers/add', server_data)
    if isinstance(result, dict) and 'Server' in result:
        print(f'Registered: server_id={result[\"Server\"][\"id\"]}')
    else:
        print(f'Result: {json.dumps(result)[:200]}')
" 2>&1

# Step 4: Register MISP-A as sync server on MISP-B
echo "[4/5] Registering MISP-A on MISP-B..."
docker compose exec -T cyberscale-web python -c "
from pymisp import PyMISP
import warnings, json
warnings.filterwarnings('ignore')
misp = PyMISP('https://misp-b', '${MISP_B_KEY}', ssl=False, timeout=30)

servers = misp.direct_call('servers/index')
server_list = servers if isinstance(servers, list) else []
a_exists = any(s.get('Server', s).get('url') == 'https://misp' for s in server_list)

if a_exists:
    print('Already registered')
else:
    server_data = {'Server': {'url': 'https://misp', 'authkey': '${SYNC_A_KEY}', 'name': 'MISP-A (Entity)', 'remote_org_id': 1, 'push': True, 'pull': True, 'self_signed': True, 'caching_enabled': False}}
    result = misp.direct_call('servers/add', server_data)
    if isinstance(result, dict) and 'Server' in result:
        print(f'Registered: server_id={result[\"Server\"][\"id\"]}')
    else:
        print(f'Result: {json.dumps(result)[:200]}')
" 2>&1

# Step 5: Test connections
echo "[5/5] Testing sync connections..."
docker compose exec -T cyberscale-web python -c "
from pymisp import PyMISP
import warnings
warnings.filterwarnings('ignore')

misp_a = PyMISP('https://misp', '${MISP_A_KEY}', ssl=False, timeout=30)
servers_a = misp_a.direct_call('servers/index')
for s in (servers_a if isinstance(servers_a, list) else []):
    srv = s.get('Server', s)
    if srv.get('url') == 'https://misp-b':
        result = misp_a.direct_call(f'servers/testConnection/{srv[\"id\"]}')
        status = result.get('status', result) if isinstance(result, dict) else str(result)
        print(f'A -> B: {status}')

misp_b = PyMISP('https://misp-b', '${MISP_B_KEY}', ssl=False, timeout=30)
servers_b = misp_b.direct_call('servers/index')
for s in (servers_b if isinstance(servers_b, list) else []):
    srv = s.get('Server', s)
    if srv.get('url') == 'https://misp':
        result = misp_b.direct_call(f'servers/testConnection/{srv[\"id\"]}')
        status = result.get('status', result) if isinstance(result, dict) else str(result)
        print(f'B -> A: {status}')
" 2>&1

echo ""
echo "===================================="
echo "Sync configured."
echo "  MISP-A (entity):    https://localhost:8443"
echo "  MISP-B (authority): https://localhost:8444"
echo "===================================="
