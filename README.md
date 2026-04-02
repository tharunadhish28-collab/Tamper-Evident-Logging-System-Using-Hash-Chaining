# Tamper-Evident Logging System

A Python-based secure logging system where log entries are cryptographically
chained using SHA-256 hashing, making any modification, deletion, or reordering
of entries immediately detectable.

---

## Project Overview

This project implements a **tamper-evident log chain** — a lightweight version
of the core idea behind blockchains. Every log entry is sealed with a SHA-256
hash that covers all of its fields, including the hash of the previous entry.
This creates an unbreakable chain: touching any entry breaks every link that
follows it.

---

## Project Structure

```
task1_tamper_logs/
├── tamper_log.py   # Main application
├── logs.json       # Persistent log storage (auto-created)
└── README.md       # This file
```

---

## Features

- SHA-256 cryptographic hash chaining between log entries
- Persistent JSON storage (`logs.json`)
- Detects three types of tampering:
  - **Modification** — any field in an entry is changed
  - **Deletion** — one or more entries are removed from the chain
  - **Reordering** — entries are shuffled out of sequence
- Pinpoints the **exact entry** where tampering is first detected
- Built-in tampering simulator for live demonstration
- Simple command-line menu interface

---

## How It Works

### Hash Chaining

```
[Entry 1]                  [Entry 2]                  [Entry 3]
previous_hash = 0000...    previous_hash = hash(E1)   previous_hash = hash(E2)
current_hash  = hash(E1)   current_hash  = hash(E2)   current_hash  = hash(E3)
```

Each `current_hash` is computed from:

```
SHA-256( log_id + timestamp + event_type + description + previous_hash )
```

### Verification Checks (in order)

| # | Check | Detects |
|---|-------|---------|
| 1 | `log_id` increments by 1 | Deletion, reordering |
| 2 | Recomputed hash == stored `current_hash` | Field modification |
| 3 | `previous_hash` == prior entry's `current_hash` | Deletion, reordering |

---

## How to Run

**Requirements:** Python 3.6+ (no third-party packages needed)

```bash
cd task1_tamper_logs
python tamper_log.py
```

---

## Sample Usage

### Normal flow — add entries and verify

```
╔══════════════════════════════════════╗
║   Tamper-Evident Logging System      ║
╚══════════════════════════════════════╝

--- Menu ---
  1. Add Log Entry
  2. View All Logs
  3. Verify Log Integrity
  4. Simulate Tampering
  5. Exit

Enter your choice (1-5): 1

--- Add New Log Entry ---
Enter event type (e.g., LOGIN, ERROR, ACCESS): LOGIN
Enter description: Admin logged in from 192.168.1.10

[+] Log entry #1 added successfully.
    Hash: 3f4a2c1e...

Enter your choice (1-5): 1

--- Add New Log Entry ---
Enter event type: ACCESS
Enter description: Read /etc/passwd

[+] Log entry #2 added successfully.
    Hash: 9b7d0e3a...

Enter your choice (1-5): 3

--- Verifying Log Chain Integrity ---

[OK] All 2 log entries are VALID. The chain is intact.
```

### Tampering demonstration

```
Enter your choice (1-5): 4

--- Simulate Tampering (Demo Only) ---
Available log IDs: [1, 2]
Enter the Log ID to tamper with: 1

Current description : "Admin logged in from 192.168.1.10"
Enter the forged description  : Admin logged in from 10.0.0.1

[!] Log ID 1 has been tampered (description changed, hash NOT updated).
    Run 'Verify Log Integrity' to see the system detect this.

Enter your choice (1-5): 3

--- Verifying Log Chain Integrity ---

[TAMPERED] Hash mismatch detected at Log ID 1.
           Stored  : 3f4a2c1e...
           Expected: d82b9f7c...
           This entry's content has been modified.

[FAIL] Log chain integrity check FAILED. Tampering detected (see above).
```

### View all logs

```
Enter your choice (1-5): 2

=================================================================
  ID    Timestamp              Event        Description
=================================================================
  1     2025-07-10 14:22:01    LOGIN        Admin logged in from 192.168.1.10
        prev : 0000000000000000000000...
        curr : 3f4a2c1e9b7d0e3a2f1c...
  ---------------------------------------------------------------
  2     2025-07-10 14:22:45    ACCESS       Read /etc/passwd
        prev : 3f4a2c1e9b7d0e3a2f1c...
        curr : 9b7d0e3a4c2f1e8d7b6a...
  ---------------------------------------------------------------
```

---

## Limitations

- The log file (`logs.json`) is stored in plain text — anyone with file system
  access can edit it. The system detects the edit but cannot prevent it.
- No encryption or access control is applied to the log file itself.
- The chain only detects tampering; it does not restore the original data.
- Not suitable for high-throughput production logging without performance tuning.

---

## Future Improvements

- Encrypt `logs.json` with AES to prevent direct file inspection
- Add file-level HMAC with a secret key to prevent wholesale chain replacement
- Export verified logs to CSV or HTML report
- Add log severity levels (INFO, WARNING, CRITICAL)
- Integrate with `syslog` or a remote logging server for off-site storage
