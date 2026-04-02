"""
Tamper-Evident Logging System
==============================
Mechanism Overview:
-------------------
This system creates a cryptographic chain of log entries, similar to how a
blockchain works.

Each log entry contains:
  - Its own SHA-256 hash (current_hash), computed from ALL its fields.
  - The hash of the previous entry (previous_hash), linking them together.

Why is this tamper-evident?
  - MODIFY  : If you change any field in an entry, its recomputed hash will no
              longer match the stored current_hash  →  detected.
  - DELETE  : The next entry's previous_hash will point to a hash that no longer
              exists in the chain, breaking the link  →  detected.
  - REORDER : The previous_hash chain will be out of sequence AND log IDs will
              no longer be sequential  →  both are detected during verification.

The very first entry uses GENESIS_HASH ("0" * 64) as its previous_hash because
there is no entry before it.
"""

import hashlib
import json
import os
from datetime import datetime

# Path to the persistent log storage file
LOG_FILE = "logs.json"

# Placeholder hash used as previous_hash for the first log entry
GENESIS_HASH = "0" * 64


# ─────────────────────────────────────────────────────────────────────────────
# FILE I/O
# ─────────────────────────────────────────────────────────────────────────────

def load_logs():
    """Load and return the list of log entries from logs.json.
    Returns an empty list if the file is missing, empty, or corrupted."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            data = json.load(f)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []


def save_logs(logs):
    """Persist the list of log entries to logs.json with readable formatting."""
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)


# ─────────────────────────────────────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────────────────────────────────────

def calculate_hash(log_id, timestamp, event_type, description, previous_hash):
    """Compute the SHA-256 hash for a log entry.

    All five fields are joined into one string before hashing, so changing
    ANY single field produces a completely different hash value.
    """
    raw = f"{log_id}{timestamp}{event_type}{description}{previous_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# CORE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def add_log():
    """Prompt the user for event details, build a chained log entry, and save it."""
    logs = load_logs()

    # Use the last entry's hash to link the new entry, or GENESIS_HASH if chain is empty
    previous_hash = logs[-1]["current_hash"] if logs else GENESIS_HASH

    log_id    = len(logs) + 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n--- Add New Log Entry ---")
    event_type  = input("Enter event type (e.g., LOGIN, ERROR, ACCESS): ").strip()
    description = input("Enter description: ").strip()

    # Compute the hash that cryptographically seals this entry
    current_hash = calculate_hash(log_id, timestamp, event_type, description, previous_hash)

    entry = {
        "log_id":        log_id,
        "timestamp":     timestamp,
        "event_type":    event_type,
        "description":   description,
        "previous_hash": previous_hash,
        "current_hash":  current_hash,
    }

    logs.append(entry)
    save_logs(logs)
    print(f"\n[+] Log entry #{log_id} added successfully.")
    print(f"    Hash: {current_hash}")


def view_logs():
    """Display all stored log entries in a readable table format."""
    logs = load_logs()

    if not logs:
        print("\n[!] No log entries found.")
        return

    print(f"\n{'='*65}")
    print(f"  {'ID':<5} {'Timestamp':<22} {'Event':<12} Description")
    print(f"{'='*65}")
    for entry in logs:
        print(f"  {entry['log_id']:<5} {entry['timestamp']:<22} {entry['event_type']:<12} {entry['description']}")
        print(f"        prev : {entry['previous_hash'][:24]}...")
        print(f"        curr : {entry['current_hash'][:24]}...")
        print(f"  {'-'*63}")


def verify_logs():
    """Verify the integrity of the entire log chain.

    Three checks are performed for every entry:
      1. Sequential IDs  – log_id must increment by exactly 1 (detects deletion/reorder).
      2. Hash integrity  – recompute the hash and compare with stored current_hash
                           (detects field modification).
      3. Chain linkage   – previous_hash must match the prior entry's current_hash
                           (detects deletion or reordering between entries).
    """
    logs = load_logs()

    if not logs:
        print("\n[!] No logs to verify.")
        return

    print("\n--- Verifying Log Chain Integrity ---")
    chain_valid = True

    for i, entry in enumerate(logs):
        log_id      = entry["log_id"]
        expected_id = i + 1

        # Check 1: Sequential log IDs
        if log_id != expected_id:
            print(f"\n[TAMPERED] Log ID mismatch at position {i + 1}.")
            print(f"           Expected ID {expected_id}, found ID {log_id}.")
            print("           Possible deletion or reordering detected.")
            chain_valid = False
            break

        # Check 2: Hash integrity — recompute and compare
        recomputed = calculate_hash(
            entry["log_id"],
            entry["timestamp"],
            entry["event_type"],
            entry["description"],
            entry["previous_hash"],
        )
        if recomputed != entry["current_hash"]:
            print(f"\n[TAMPERED] Hash mismatch detected at Log ID {log_id}.")
            print(f"           Stored  : {entry['current_hash']}")
            print(f"           Expected: {recomputed}")
            print("           This entry's content has been modified.")
            chain_valid = False
            break

        # Check 3: Chain linkage — previous_hash must match prior entry's current_hash
        expected_prev = GENESIS_HASH if i == 0 else logs[i - 1]["current_hash"]
        if entry["previous_hash"] != expected_prev:
            print(f"\n[TAMPERED] Chain break detected at Log ID {log_id}.")
            print(f"           Stored previous_hash : {entry['previous_hash']}")
            print(f"           Expected             : {expected_prev}")
            print("           An entry may have been deleted or reordered.")
            chain_valid = False
            break

    if chain_valid:
        print(f"\n[OK] All {len(logs)} log entries are VALID. The chain is intact.")
    else:
        print("\n[FAIL] Log chain integrity check FAILED. Tampering detected (see above).")


def simulate_tampering():
    """Directly modify a stored log entry WITHOUT updating its hash.

    This simulates what a naive attacker might do, and demonstrates that
    verify_logs() will catch the change immediately.
    """
    logs = load_logs()

    if not logs:
        print("\n[!] Need at least one log entry to simulate tampering.")
        return

    print("\n--- Simulate Tampering (Demo Only) ---")
    print("Available log IDs:", [e["log_id"] for e in logs])

    try:
        target_id = int(input("Enter the Log ID to tamper with: "))
    except ValueError:
        print("[!] Invalid input. Please enter a numeric Log ID.")
        return

    # Locate the target entry
    target = next((e for e in logs if e["log_id"] == target_id), None)
    if not target:
        print(f"[!] Log ID {target_id} not found.")
        return

    print(f"\nCurrent description : \"{target['description']}\"")
    new_desc = input("Enter the forged description  : ").strip()

    # Change the description but intentionally leave current_hash unchanged —
    # this is the tamper. verify_logs() will detect the hash mismatch.
    target["description"] = new_desc
    save_logs(logs)

    print(f"\n[!] Log ID {target_id} has been tampered (description changed, hash NOT updated).")
    print("    Run 'Verify Log Integrity' to see the system detect this.")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Main menu loop — presents options and dispatches to the correct function."""
    print("\n╔══════════════════════════════════════╗")
    print("║   Tamper-Evident Logging System      ║")
    print("╚══════════════════════════════════════╝")

    menu = {
        "1": ("Add Log Entry",        add_log),
        "2": ("View All Logs",        view_logs),
        "3": ("Verify Log Integrity", verify_logs),
        "4": ("Simulate Tampering",   simulate_tampering),
        "5": ("Exit",                 None),
    }

    while True:
        print("\n--- Menu ---")
        for key, (label, _) in menu.items():
            print(f"  {key}. {label}")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "5":
            print("\n[*] Exiting. Goodbye!")
            break
        elif choice in menu:
            _, action = menu[choice]
            action()
        else:
            print("[!] Invalid choice. Please enter a number between 1 and 5.")


if __name__ == "__main__":
    main()
