#!/usr/bin/env python3
"""
============================================================
FILE INTEGRITY MONITOR (FIM)
Author: Sanketh Subhas
GitHub: github.com/SankethSubhas
============================================================
Detects unauthorized file changes, deletions, and additions.
Maps events to MITRE ATT&CK techniques.
============================================================
"""

import os
import hashlib
import json
import argparse
import logging
from datetime import datetime

# ── MITRE ATT&CK MAPPINGS ───────────────────────────────────
MITRE_MAP = {
    "MODIFIED": {
        "technique": "T1565.001 - Stored Data Manipulation",
        "tactic":    "Impact",
        "detail":    "Adversaries may manipulate files to influence outcomes."
    },
    "DELETED": {
        "technique": "T1485 - Data Destruction",
        "tactic":    "Impact",
        "detail":    "Adversaries may destroy data to interrupt availability."
    },
    "ADDED": {
        "technique": "T1105 - Ingress Tool Transfer",
        "tactic":    "Command and Control",
        "detail":    "Adversaries may transfer tools or files into an environment."
    }
}

# ── LOGGING SETUP ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("FIM")


def hash_file(filepath: str) -> str:
    """Return SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, PermissionError) as e:
        logger.warning(f"Cannot read {filepath}: {e}")
        return "UNREADABLE"


def scan_directory(target_dir: str) -> dict:
    """Scan directory and return {filepath: hash} snapshot."""
    snapshot = {}
    for root, _, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            snapshot[filepath] = hash_file(filepath)
    return snapshot


def save_baseline(snapshot: dict, baseline_file: str):
    """Save snapshot to baseline JSON file."""
    data = {
        "created_at": datetime.now().isoformat(),
        "file_count": len(snapshot),
        "snapshot": snapshot
    }
    with open(baseline_file, "w") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Baseline saved → {baseline_file}  ({len(snapshot)} files indexed)")


def load_baseline(baseline_file: str) -> dict:
    """Load baseline from JSON file."""
    with open(baseline_file, "r") as f:
        data = json.load(f)
    created = data.get("created_at", "unknown")
    count   = data.get("file_count", 0)
    logger.info(f"Baseline loaded  ({count} files, created {created})")
    return data["snapshot"]


def compare_snapshots(baseline: dict, current: dict) -> list:
    """Compare baseline vs current snapshot and return list of events."""
    events = []

    for filepath, old_hash in baseline.items():
        if filepath not in current:
            events.append({
                "type":      "DELETED",
                "file":      filepath,
                "old_hash":  old_hash,
                "new_hash":  None,
                "timestamp": datetime.now().isoformat(),
                **MITRE_MAP["DELETED"]
            })
        elif current[filepath] != old_hash:
            events.append({
                "type":      "MODIFIED",
                "file":      filepath,
                "old_hash":  old_hash,
                "new_hash":  current[filepath],
                "timestamp": datetime.now().isoformat(),
                **MITRE_MAP["MODIFIED"]
            })

    for filepath, new_hash in current.items():
        if filepath not in baseline:
            events.append({
                "type":      "ADDED",
                "file":      filepath,
                "old_hash":  None,
                "new_hash":  new_hash,
                "timestamp": datetime.now().isoformat(),
                **MITRE_MAP["ADDED"]
            })

    return events


def print_report(events: list, log_file: str = None):
    """Print a clean report of all detected events."""
    divider = "=" * 65

    print(f"\n{divider}")
    print("  FILE INTEGRITY MONITOR — SCAN REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)

    if not events:
        print("\n  ✅  No changes detected. All files intact.\n")
        print(divider)
        return

    counts = {"MODIFIED": 0, "DELETED": 0, "ADDED": 0}
    for e in events:
        counts[e["type"]] += 1

    print(f"\n  ⚠️  TOTAL EVENTS DETECTED: {len(events)}")
    print(f"     MODIFIED : {counts['MODIFIED']}")
    print(f"     DELETED  : {counts['DELETED']}")
    print(f"     ADDED    : {counts['ADDED']}")
    print()

    for e in events:
        tag = {
            "MODIFIED": "⚠️  MODIFIED",
            "DELETED":  "❌  DELETED ",
            "ADDED":    "🆕  ADDED   "
        }[e["type"]]

        print(f"  {tag}  {e['file']}")
        print(f"           MITRE   : {e['technique']}")
        print(f"           Tactic  : {e['tactic']}")
        print(f"           Detail  : {e['detail']}")
        if e["old_hash"]:
            print(f"           Old Hash: {e['old_hash'][:16]}...")
        if e["new_hash"]:
            print(f"           New Hash: {e['new_hash'][:16]}...")
        print()

    print(divider)

    if log_file:
        with open(log_file, "a") as f:
            f.write(f"\n{'='*65}\n")
            f.write(f"SCAN REPORT — {datetime.now().isoformat()}\n")
            f.write(f"Total Events: {len(events)}\n\n")
            for e in events:
                f.write(f"[{e['type']}] {e['file']}\n")
                f.write(f"  MITRE    : {e['technique']}\n")
                f.write(f"  Tactic   : {e['tactic']}\n")
                f.write(f"  Old Hash : {e['old_hash']}\n")
                f.write(f"  New Hash : {e['new_hash']}\n")
                f.write(f"  Time     : {e['timestamp']}\n\n")
        logger.info(f"Events logged → {log_file}")


# ── MAIN ─────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — Detect unauthorized file changes",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("mode", choices=["baseline", "scan"],
        help="baseline  → Create initial snapshot\nscan      → Compare against baseline")
    parser.add_argument("--dir",      default=".",         help="Directory to monitor (default: current)")
    parser.add_argument("--baseline", default="baseline.json", help="Baseline file path (default: baseline.json)")
    parser.add_argument("--log",      default="fim_log.txt",   help="Log file path (default: fim_log.txt)")

    args = parser.parse_args()
    target_dir    = os.path.abspath(args.dir)
    baseline_file = args.baseline
    log_file      = args.log

    print(f"\n  📂  Target Directory : {target_dir}")
    print(f"  📄  Baseline File    : {baseline_file}")
    print(f"  📝  Log File         : {log_file}\n")

    if args.mode == "baseline":
        logger.info("Mode: BASELINE — Scanning directory...")
        snapshot = scan_directory(target_dir)
        save_baseline(snapshot, baseline_file)
        logger.info("✅  Baseline created successfully.")

    elif args.mode == "scan":
        if not os.path.exists(baseline_file):
            logger.error(f"Baseline file not found: {baseline_file}")
            logger.error("Run with 'baseline' mode first.")
            return

        logger.info("Mode: SCAN — Comparing against baseline...")
        baseline = load_baseline(baseline_file)
        current  = scan_directory(target_dir)
        events   = compare_snapshots(baseline, current)
        print_report(events, log_file)

        if events:
            logger.warning(f"{len(events)} integrity violation(s) detected!")
        else:
            logger.info("✅  Scan complete. No violations found.")


if __name__ == "__main__":
    main()
