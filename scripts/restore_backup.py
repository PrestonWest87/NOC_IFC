#!/usr/bin/env python3
"""Restore a validated encrypted backup while application writers are stopped."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core import restore_control
from src.core.backup_manager import BackupError, restore_backup


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="Encrypted .nocbackup file to restore")
    parser.add_argument(
        "--maintenance-confirmed",
        action="store_true",
        help="Confirm that the API, worker, and webhook services have been stopped.",
    )
    args = parser.parse_args()
    try:
        if args.maintenance_confirmed:
            pending = restore_control.active_restore()
            if pending and pending.get("restore_id"):
                restore_control.finish_restore(
                    pending["restore_id"], "error", "UI restore was superseded by the offline restore command."
                )
        result = restore_backup(args.backup, maintenance_confirmed=args.maintenance_confirmed)
    except (BackupError, OSError) as exc:
        parser.exit(1, f"Restore failed: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
