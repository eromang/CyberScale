"""Push CyberScale assessment events to a MISP instance via PyMISP."""

from __future__ import annotations

import logging
from datetime import date

from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP

logger = logging.getLogger("cyberscale.misp_push")


def push_event(misp_url: str, misp_api_key: str, event_dict: dict, ssl: bool = True) -> dict:
    """Push a CyberScale MISP event dict to a remote MISP instance.

    Args:
        misp_url: Base URL of the MISP instance (e.g. https://misp.example.org).
        misp_api_key: API key for authentication.
        event_dict: Event dict as produced by misp_export builders (has "Event" key).
        ssl: Whether to verify SSL certificates (False for self-signed).

    Returns:
        dict with keys:
            success (bool), event_id (str|None), event_uuid (str|None),
            error (str|None)
    """
    try:
        misp = PyMISP(misp_url, misp_api_key, ssl=ssl, timeout=30)
    except Exception as exc:
        logger.error("Failed to connect to MISP at %s: %s", misp_url, exc)
        return {"success": False, "event_id": None, "event_uuid": None, "error": str(exc)}

    try:
        response = misp.direct_call("events/add", event_dict)

        if isinstance(response, dict) and "errors" in response:
            error_msg = str(response["errors"])
            logger.error("MISP push rejected: %s", error_msg)
            return {"success": False, "event_id": None, "event_uuid": None, "error": error_msg}

        if isinstance(response, dict):
            evt = response.get("Event", response)
            event_id = str(evt.get("id", ""))
            event_uuid = str(evt.get("uuid", ""))
        else:
            # MISPEvent object or compatible (has .id and .uuid)
            event_id = str(response.id) if hasattr(response, "id") else ""
            event_uuid = str(response.uuid) if hasattr(response, "uuid") else ""

        logger.info("MISP push successful: event_id=%s uuid=%s", event_id, event_uuid)
        return {"success": True, "event_id": event_id, "event_uuid": event_uuid, "error": None}

    except Exception as exc:
        logger.error("MISP push failed: %s", exc)
        return {"success": False, "event_id": None, "event_uuid": None, "error": str(exc)}


def _dict_to_misp_event(event_data: dict) -> MISPEvent:
    """Convert a CyberScale event dict into a MISPEvent object."""
    event = MISPEvent()
    event.info = event_data.get("info", "CyberScale entity assessment")
    event.date = event_data.get("date") or date.today().isoformat()
    event.threat_level_id = int(event_data.get("threat_level_id", 2))
    event.analysis = int(event_data.get("analysis", 2))
    event.distribution = int(event_data.get("distribution", 1))

    if event_data.get("uuid"):
        event.uuid = event_data["uuid"]

    for tag in event_data.get("Tag", []):
        event.add_tag(tag["name"])

    for obj_data in event_data.get("Object", []):
        obj_name = obj_data.get("name", "cyberscale-entity-assessment")
        misp_obj = MISPObject(obj_name, standalone=True)
        if obj_data.get("uuid"):
            misp_obj.uuid = obj_data["uuid"]

        for attr_data in obj_data.get("Attribute", []):
            misp_attr = MISPAttribute()
            misp_attr.object_relation = attr_data.get("object_relation", "")
            misp_attr.type = attr_data.get("type", "text")
            misp_attr.value = attr_data.get("value", "")
            misp_obj.Attribute.append(misp_attr)

        for ref_data in obj_data.get("ObjectReference", []):
            from pymisp import MISPObjectReference
            ref = MISPObjectReference()
            ref.referenced_uuid = ref_data.get("referenced_uuid", "")
            ref.relationship_type = ref_data.get("relationship_type", "")
            ref.comment = ref_data.get("comment", "")
            misp_obj.ObjectReference.append(ref)

        event.Object.append(misp_obj)

    return event
