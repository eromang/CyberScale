"""End-to-end sync tests between MISP-A and MISP-B.

Requires both MISP instances running with sync configured.
Set MISP_URL, MISP_API_KEY, MISP_B_URL, MISP_B_API_KEY environment variables.

Run with:
  docker compose exec \
    -e MISP_URL=https://misp -e MISP_API_KEY=<a-key> \
    -e MISP_B_URL=https://misp-b -e MISP_B_API_KEY=<b-key> \
    cyberscale-web python -m pytest entity/tests/test_misp_sync.py -v
"""

import os
import time
import uuid

import pytest
from django.test import TestCase


MISP_URL = os.environ.get("MISP_URL", "")
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")
MISP_B_URL = os.environ.get("MISP_B_URL", "")
MISP_B_API_KEY = os.environ.get("MISP_B_API_KEY", "")

_PLACEHOLDER_KEYS = {"changeme-run-misp-authkey-setup", "changeme-run-misp-b-init", ""}

requires_sync = pytest.mark.skipif(
    not MISP_URL or MISP_API_KEY in _PLACEHOLDER_KEYS
    or not MISP_B_URL or MISP_B_API_KEY in _PLACEHOLDER_KEYS,
    reason="MISP_URL/MISP_API_KEY/MISP_B_URL/MISP_B_API_KEY not set",
)


def _get_misp(url, key):
    from pymisp import PyMISP
    return PyMISP(url, key, ssl=False, timeout=30)


def _trigger_push(misp, server_name):
    """Find sync server by name and trigger push."""
    servers = misp.direct_call("servers/index")
    for s in (servers if isinstance(servers, list) else []):
        srv = s.get("Server", s)
        if server_name.lower() in srv.get("name", "").lower():
            misp.direct_call(f"servers/push/{srv['id']}/full")
            return srv["id"]
    return None


def _trigger_pull(misp, server_name):
    """Find sync server by name and trigger pull."""
    servers = misp.direct_call("servers/index")
    for s in (servers if isinstance(servers, list) else []):
        srv = s.get("Server", s)
        if server_name.lower() in srv.get("name", "").lower():
            misp.direct_call(f"servers/pull/{srv['id']}/full")
            return srv["id"]
    return None


def _wait_for_event(misp, event_uuid, max_wait=15):
    """Poll for event by UUID until found or timeout."""
    for _ in range(max_wait):
        results = misp.direct_call("events/restSearch", {"uuid": event_uuid})
        if isinstance(results, list) and results:
            return results[0].get("Event", results[0])
        if isinstance(results, dict) and results.get("response"):
            resp = results["response"]
            if resp:
                return resp[0].get("Event", resp[0])
        time.sleep(1)
    return None


@requires_sync
class MISPSyncProfileTest(TestCase):
    """Test 1: Profile push propagates A -> B."""

    def test_profile_propagates_a_to_b(self):
        misp_a = _get_misp(MISP_URL, MISP_API_KEY)
        misp_b = _get_misp(MISP_B_URL, MISP_B_API_KEY)

        event_uuid = str(uuid.uuid4())
        event_dict = {
            "Event": {
                "info": f"Sync test profile {event_uuid[:8]}",
                "uuid": event_uuid,
                "threat_level_id": "4",
                "analysis": "2",
                "distribution": "3",
                "Tag": [{"name": "tlp:amber"}],
                "Object": [{
                    "name": "cyberscale-entity-profile",
                    "meta-category": "misc",
                    "template_uuid": "c5e0f001-e27a-4f00-a000-000000000001",
                    "template_version": "1",
                    "Attribute": [
                        {"object_relation": "organisation-name", "type": "text", "value": "SyncTest Corp"},
                        {"object_relation": "ms-established", "type": "text", "value": "LU"},
                    ],
                }],
            }
        }

        result = misp_a.direct_call("events/add", event_dict)
        assert "Event" in result, f"Push to A failed: {result}"

        _trigger_push(misp_a, "MISP-B")
        time.sleep(3)

        event_b = _wait_for_event(misp_b, event_uuid)
        assert event_b is not None, "Event did not propagate to MISP-B"
        assert event_b["info"] == f"Sync test profile {event_uuid[:8]}"


@requires_sync
class MISPSyncAssessmentTest(TestCase):
    """Test 2: Assessment + early warning propagates A -> B."""

    def test_assessment_with_ew_propagates(self):
        misp_a = _get_misp(MISP_URL, MISP_API_KEY)
        misp_b = _get_misp(MISP_B_URL, MISP_B_API_KEY)

        event_uuid = str(uuid.uuid4())
        event_dict = {
            "Event": {
                "info": f"Sync test assessment {event_uuid[:8]}",
                "uuid": event_uuid,
                "threat_level_id": "1",
                "analysis": "2",
                "distribution": "3",
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": 'nis2:notification-stage="early-warning"'},
                    {"name": 'cyberscale:notification-status="received"'},
                ],
                "Object": [
                    {
                        "name": "cyberscale-entity-assessment",
                        "meta-category": "misc",
                        "template_uuid": "c5e0f001-e27a-4f00-a000-000000000002",
                        "template_version": "2",
                        "Attribute": [
                            {"object_relation": "sector", "type": "text", "value": "energy"},
                            {"object_relation": "significant-incident", "type": "boolean", "value": "1"},
                        ],
                    },
                    {
                        "name": "cyberscale-early-warning",
                        "meta-category": "misc",
                        "template_uuid": "c5e0f001-e27a-4f00-a000-000000000003",
                        "template_version": "1",
                        "Attribute": [
                            {"object_relation": "deadline", "type": "text", "value": "24h"},
                            {"object_relation": "suspected-malicious", "type": "boolean", "value": "1"},
                        ],
                    },
                ],
            }
        }

        result = misp_a.direct_call("events/add", event_dict)
        assert "Event" in result

        _trigger_push(misp_a, "MISP-B")
        time.sleep(3)

        event_b = _wait_for_event(misp_b, event_uuid)
        assert event_b is not None, "Assessment event did not propagate"
        assert len(event_b.get("Object", [])) >= 1


@requires_sync
class MISPSyncTagUpdateTest(TestCase):
    """Test 3: Lifecycle tag update propagates A -> B."""

    def test_tag_update_propagates(self):
        from entity.misp_push import update_event_tags

        misp_a = _get_misp(MISP_URL, MISP_API_KEY)
        misp_b = _get_misp(MISP_B_URL, MISP_B_API_KEY)

        event_uuid = str(uuid.uuid4())
        event_dict = {
            "Event": {
                "info": f"Sync tag test {event_uuid[:8]}",
                "uuid": event_uuid,
                "threat_level_id": "1",
                "analysis": "2",
                "distribution": "3",
                "Tag": [{"name": 'cyberscale:notification-status="received"'}],
                "Object": [],
            }
        }

        result = misp_a.direct_call("events/add", event_dict)
        assert "Event" in result
        event_id = result["Event"]["id"]

        _trigger_push(misp_a, "MISP-B")
        time.sleep(3)

        update_event_tags(
            MISP_URL, MISP_API_KEY, event_id,
            remove_prefix="cyberscale:notification-status",
            add_tag='cyberscale:notification-status="acknowledged"',
            ssl=False,
        )

        _trigger_push(misp_a, "MISP-B")
        time.sleep(3)

        event_b = _wait_for_event(misp_b, event_uuid)
        assert event_b is not None
        tags_b = [t["name"] for t in event_b.get("Tag", [])]
        assert 'cyberscale:notification-status="acknowledged"' in tags_b


@requires_sync
class MISPSyncFeedbackTest(TestCase):
    """Test 4: B -> A feedback (authority creates event on B, syncs to A)."""

    def test_feedback_b_to_a(self):
        misp_a = _get_misp(MISP_URL, MISP_API_KEY)
        misp_b = _get_misp(MISP_B_URL, MISP_B_API_KEY)

        event_uuid = str(uuid.uuid4())
        event_dict = {
            "Event": {
                "info": f"Authority feedback {event_uuid[:8]}",
                "uuid": event_uuid,
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "3",
                "Tag": [{"name": "tlp:green"}],
                "Object": [],
            }
        }

        result = misp_b.direct_call("events/add", event_dict)
        assert "Event" in result

        _trigger_push(misp_b, "MISP-A")
        time.sleep(3)

        event_a = _wait_for_event(misp_a, event_uuid)
        assert event_a is not None, "Feedback event did not propagate B -> A"
        assert "Authority feedback" in event_a["info"]


@requires_sync
class MISPSyncTemplatesTest(TestCase):
    """Test 5: Custom templates available on MISP-B."""

    def test_templates_registered_on_b(self):
        misp_b = _get_misp(MISP_B_URL, MISP_B_API_KEY)

        templates = misp_b.direct_call("objectTemplates/index")
        template_names = [t.get("ObjectTemplate", t).get("name", "") for t in (templates if isinstance(templates, list) else [])]

        assert "cyberscale-entity-profile" in template_names
        assert "cyberscale-entity-assessment" in template_names
        assert "cyberscale-early-warning" in template_names
