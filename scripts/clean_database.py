"""
APEXEYE — Database & Environment Reset Utility

Clears all stored records, alerts, audit logs, commands, CCTV records,
AWS instances, telemetry, and device records from the centralized SQLite database.
Resets SQLite sequence counters, vacuums the database file, and optionally
clears stale application log files for a fresh start.
"""

import argparse
import os
import sqlite3
from pathlib import Path


def clean_database(db_path: Path, reset_logs: bool = False, reset_reports: bool = False) -> None:
    if not db_path.exists():
        print(f"[!] Database file does not exist at: {db_path}")
        return

    print(f"[*] Connecting to database: {db_path}")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("PRAGMA foreign_keys = OFF;")

    # Discover all user tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in cur.fetchall()]

    print(f"[*] Found {len(tables)} tables to clear: {', '.join(tables)}")

    total_deleted = 0
    for table in tables:
        count = cur.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
        cur.execute(f"DELETE FROM {table};")
        total_deleted += count
        print(f"    - Cleared {table:20s}: {count:5d} row(s) deleted")

    # Reset SQLite autoincrement sequence counters
    try:
        cur.execute("DELETE FROM sqlite_sequence;")
        print("    - Cleared sqlite_sequence (all AUTOINCREMENT counters reset to 1)")
    except sqlite3.OperationalError:
        pass

    conn.commit()

    print("[*] Running VACUUM to reclaim disk space and defragment database...")
    cur.execute("VACUUM;")
    conn.close()

    # Reopen to verify
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchone()[0]
    print(f"[OK] Database integrity check: {integrity}")

    # Display final row counts
    all_zero = True
    for table in tables:
        cnt = cur.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
        if cnt != 0:
            all_zero = False
            print(f"    [!] Warning: {table} still has {cnt} rows!")
    conn.close()

    if all_zero:
        print(f"[OK] All {len(tables)} tables successfully cleared (0 rows remaining). Total deleted: {total_deleted} rows.")

    # Reset logs if requested
    if reset_logs:
        log_paths = [
            Path("logs/master.log"),
            Path("logs/client.log"),
            Path("logs/client_linux.log"),
            Path("client/logs/client.log"),
            Path("client_linux/logs/client_linux.log"),
        ]
        print("[*] Truncating log files...")
        for lp in log_paths:
            if lp.exists():
                size_before = lp.stat().st_size
                with open(lp, "w", encoding="utf-8") as f:
                    f.truncate(0)
                print(f"    - Truncated {lp} ({size_before} bytes -> 0 bytes)")

    # Reset reports if requested
    if reset_reports:
        reports_dir = Path("reports")
        if reports_dir.exists():
            pdfs = list(reports_dir.glob("*.pdf"))
            print(f"[*] Removing {len(pdfs)} generated test reports...")
            for pdf in pdfs:
                try:
                    pdf.unlink()
                    print(f"    - Deleted {pdf.name}")
                except Exception as e:
                    print(f"    - Failed to delete {pdf.name}: {e}")

    # Remove temporary scratch db if present
    scratch_db = Path("scratch/verify_phase9_2_1.db")
    if scratch_db.exists():
        try:
            scratch_db.unlink()
            print(f"[OK] Removed scratch database: {scratch_db}")
        except Exception as e:
            print(f"[!] Could not remove {scratch_db}: {e}")

    print("\n[OK] Fresh database state ready. All test records and garbage wiped cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset APEXEYE database and clean test artifacts.")
    parser.add_argument("--db-path", default="database/apexeye.db", help="Path to SQLite database file")
    parser.add_argument("--clear-logs", action="store_true", default=True, help="Truncate log files on disk")
    parser.add_argument("--clear-reports", action="store_true", default=True, help="Remove generated PDF test reports")
    args = parser.parse_args()

    clean_database(
        db_path=Path(args.db_path),
        reset_logs=args.clear_logs,
        reset_reports=args.clear_reports,
    )
