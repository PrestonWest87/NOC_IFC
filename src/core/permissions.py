"""Load the shared permission contract and expose backend lookup keys."""

import json
from pathlib import Path

_CATALOG_PATH = Path(__file__).resolve().parents[2] / "contracts" / "permission_catalog.json"
with _CATALOG_PATH.open(encoding="utf-8") as catalog_file:
    _CATALOG = json.load(catalog_file)

PAGE_CATALOG = _CATALOG["pages"]
ACTION_CATALOG = _CATALOG["actions"]
TAB_CATALOG = _CATALOG["tabs"]

PAGE_KEYS = [item["key"] for item in PAGE_CATALOG]
ACTION_KEYS = [item["key"] for item in ACTION_CATALOG]
TAB_KEYS = [item["key"] for tabs in TAB_CATALOG.values() for item in tabs]
ADMIN_ACTIONS = [*ACTION_KEYS, *TAB_KEYS]


def public_permission_catalog() -> dict:
    """Return the shared permission schema consumed by the role-management UI."""
    return {
        "pages": PAGE_CATALOG,
        "actions": ACTION_CATALOG,
        "tabs": TAB_CATALOG,
    }
