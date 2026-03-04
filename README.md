# File Integrity Monitor (FIM)

A lightweight Python-based File Integrity Monitor that detects unauthorized file modifications, deletions, and additions. All events are mapped to **MITRE ATT&CK** techniques and logged with timestamps.

---

## What It Does

- Scans a target directory and creates a SHA-256 baseline snapshot
- Re-scans and compares against the baseline to detect:
  - **Modified** files → `T1565.001 - Stored Data Manipulation`
  - **Deleted** files → `T1485 - Data Destruction`
  - **Added** files → `T1105 - Ingress Tool Transfer`
- Generates a clean terminal report
- Logs all events to a file for audit trail

---

## Usage

### Step 1 — Create Baseline
```bash
python3 fim.py baseline --dir /path/to/monitor
```

### Step 2 — Run Scan
```bash
python3 fim.py scan --dir /path/to/monitor
```

### Optional Arguments
| Argument | Default | Description |
|---|---|---|
| `--dir` | `.` (current) | Directory to monitor |
| `--baseline` | `baseline.json` | Baseline snapshot file |
| `--log` | `fim_log.txt` | Output log file |

---

## Sample Output

```
=================================================================
  FILE INTEGRITY MONITOR — SCAN REPORT
  2026-03-04 14:22:10
=================================================================

  ⚠️  TOTAL EVENTS DETECTED: 3
     MODIFIED : 1
     DELETED  : 1
     ADDED    : 1

  ⚠️  MODIFIED  /var/www/html/index.php
           MITRE   : T1565.001 - Stored Data Manipulation
           Tactic  : Impact
           Old Hash: a3f1c2d4e5b6a7f8...
           New Hash: 9d8c7b6a5f4e3d2c...

  ❌  DELETED   /etc/cron.d/backup_job
           MITRE   : T1485 - Data Destruction
           Tactic  : Impact

  🆕  ADDED    /tmp/.hidden_payload
           MITRE   : T1105 - Ingress Tool Transfer
           Tactic  : Command and Control

=================================================================
```

---

## MITRE ATT&CK Coverage

| Event | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| File Modified | T1565.001 | Stored Data Manipulation | Impact |
| File Deleted | T1485 | Data Destruction | Impact |
| File Added | T1105 | Ingress Tool Transfer | Command and Control |

---

## Requirements

- Python 3.6+
- No external dependencies — standard library only

---

## Real-World Use Cases

- Monitor `/etc` for unauthorized config changes
- Watch web server directories for web shell drops
- Detect ransomware activity (mass file modifications)
- Audit critical system files in a SOC environment

---

## Author

**Sanketh Subhas** — Cybersecurity Analyst  
[sankethsubhas.pages.dev](https://sankethsubhas.pages.dev) | [LinkedIn](https://linkedin.com/in/sanketh-subhas) | [GitHub](https://github.com/SankethSubhas)
