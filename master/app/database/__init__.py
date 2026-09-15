"""
APEXEYE MASTER — Database Initialization & Connection

Owns the centralized SQLite database.
The Client MUST NEVER import or use this module directly.
"""

import sqlite3
from pathlib import Path

from master.app.config import config
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.database")

# ── SQL: Table Definitions ───────────────────────────────────────────

_TABLES_SQL = """
-- Devices registered with the Master
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT    NOT NULL UNIQUE,
    device_name     TEXT    NOT NULL,
    device_type     TEXT    NOT NULL CHECK(device_type IN (
                        'WINDOWS_PC','LINUX_PC','CCTV','AWS_INSTANCE','OTHER'
                    )),
    operating_system TEXT,
    hostname        TEXT,
    ip_address      TEXT,
    location        TEXT,
    status          TEXT    NOT NULL DEFAULT 'inactive',
    authentication_status TEXT NOT NULL DEFAULT 'unauthenticated',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT
);

-- Device authentication metadata (NO plaintext secrets)
CREATE TABLE IF NOT EXISTS device_auth (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT    NOT NULL,
    credential_id       TEXT    NOT NULL,
    authentication_status TEXT  NOT NULL DEFAULT 'pending',
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at          TEXT,
    last_used_at        TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Telemetry snapshots
-- Phase 2: 'details' column stores full JSON payload for rich data
CREATE TABLE IF NOT EXISTS telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    cpu_usage       REAL,
    memory_usage    REAL,
    disk_usage      REAL,
    network_usage   REAL,
    health_score    REAL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Centralized logs (Phase 5 Enhanced)
CREATE TABLE IF NOT EXISTS logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT,
    device_type         TEXT,
    timestamp           TEXT    NOT NULL DEFAULT (datetime('now')),
    level               TEXT    NOT NULL DEFAULT 'INFO',
    severity            TEXT    NOT NULL DEFAULT 'INFO',
    event_type          TEXT    NOT NULL DEFAULT 'INFO',
    category            TEXT    NOT NULL DEFAULT 'OTHER',
    application_name    TEXT,
    message             TEXT    NOT NULL,
    source              TEXT,
    details             TEXT,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE SET NULL
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    severity        TEXT    NOT NULL,
    alert_type      TEXT    NOT NULL,
    message         TEXT,
    status          TEXT    NOT NULL DEFAULT 'open',
    acknowledged_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE SET NULL
);

-- Audit log (who did what)
CREATE TABLE IF NOT EXISTS audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    actor           TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    target          TEXT,
    details         TEXT
);

-- Reports
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type     TEXT    NOT NULL,
    generated_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    start_date      TEXT,
    end_date        TEXT,
    file_path       TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending'
);

-- Phase 10: Administrative Command Center & Remote Operations
CREATE TABLE IF NOT EXISTS commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id      TEXT    NOT NULL UNIQUE,
    device_id       TEXT    NOT NULL,
    command_type    TEXT    NOT NULL,
    parameters      TEXT,
    status          TEXT    NOT NULL DEFAULT 'PENDING',
    requested_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT,
    administrator   TEXT    NOT NULL DEFAULT 'admin',
    result          TEXT,
    error           TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Phase 4: CCTV / IP Camera Monitoring
CREATE TABLE IF NOT EXISTS cctv_devices (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cctv_id                 TEXT    NOT NULL UNIQUE,
    name                    TEXT    NOT NULL,
    ip_address              TEXT    NOT NULL,
    port                    INTEGER NOT NULL DEFAULT 554,
    rtsp_path               TEXT    DEFAULT '/stream1',
    rtsp_url                TEXT,
    username                TEXT,
    password_enc            TEXT,
    location                TEXT,
    is_enabled              INTEGER NOT NULL DEFAULT 1,
    status                  TEXT    NOT NULL DEFAULT 'UNKNOWN',
    last_status_reason      TEXT,
    last_checked            TEXT,
    last_successful_check   TEXT,
    consecutive_failures    INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Phase 4: CCTV Telemetry / Health Snapshots
CREATE TABLE IF NOT EXISTS cctv_telemetry (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cctv_id                 TEXT    NOT NULL,
    timestamp               TEXT    NOT NULL DEFAULT (datetime('now')),
    tcp_reachable           INTEGER NOT NULL DEFAULT 0,
    tcp_response_time_ms    REAL,
    rtsp_reachable          INTEGER NOT NULL DEFAULT 0,
    rtsp_response_time_ms   REAL,
    status                  TEXT    NOT NULL,
    failure_reason          TEXT,
    details                 TEXT,
    FOREIGN KEY (cctv_id) REFERENCES cctv_devices(cctv_id) ON DELETE CASCADE
);

-- AWS Cloud Monitoring (Dedicated Subsystem Tables)
CREATE TABLE IF NOT EXISTS aws_config (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_mode         TEXT    NOT NULL DEFAULT 'env',
    region                  TEXT    NOT NULL DEFAULT 'us-east-1',
    account_id              TEXT,
    connection_status       TEXT    NOT NULL DEFAULT 'Not Configured',
    last_tested_at          TEXT,
    last_error              TEXT,
    updated_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS aws_instances (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id             TEXT    NOT NULL UNIQUE,
    account_id              TEXT,
    region                  TEXT    NOT NULL,
    name                    TEXT,
    instance_type           TEXT,
    state                   TEXT    NOT NULL DEFAULT 'unknown',
    availability_zone       TEXT,
    private_ip              TEXT,
    public_ip               TEXT,
    platform                TEXT,
    launch_time             TEXT,
    system_status           TEXT    DEFAULT 'initializing',
    instance_status         TEXT    DEFAULT 'initializing',
    last_checked            TEXT,
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS aws_metrics (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id             TEXT    NOT NULL,
    region                  TEXT    NOT NULL,
    metric_name             TEXT    NOT NULL,
    timestamp               TEXT    NOT NULL DEFAULT (datetime('now')),
    value                   REAL,
    unit                    TEXT,
    source                  TEXT    NOT NULL DEFAULT 'CloudWatch',
    created_at              TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (instance_id) REFERENCES aws_instances(instance_id) ON DELETE CASCADE
);

-- Firewall subsystem tables
CREATE TABLE IF NOT EXISTS firewall_settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    enabled         INTEGER NOT NULL DEFAULT 0,
    policy_version  INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_by      TEXT    NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS firewall_blocked_domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT    NOT NULL,
    normalized_domain TEXT NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by      TEXT    NOT NULL DEFAULT 'admin',
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT,
    device_name     TEXT,
    domain          TEXT    NOT NULL,
    url             TEXT,
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
    action          TEXT    NOT NULL DEFAULT 'BLOCKED',
    policy_version  INTEGER NOT NULL DEFAULT 0,
    platform        TEXT,
    destination_ip  TEXT,
    metadata        TEXT,
    dedup_key       TEXT    UNIQUE
);
"""

_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_devices_device_id    ON devices(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_status       ON devices(status);
CREATE INDEX IF NOT EXISTS idx_device_auth_device   ON device_auth(device_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_device     ON telemetry(device_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp  ON telemetry(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_device          ON logs(device_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp       ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_event_type      ON logs(event_type);
CREATE INDEX IF NOT EXISTS idx_logs_severity        ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_category        ON logs(category);
CREATE INDEX IF NOT EXISTS idx_logs_app_name        ON logs(application_name);
CREATE INDEX IF NOT EXISTS idx_alerts_device        ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status        ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_cctv_devices_cctv_id ON cctv_devices(cctv_id);
CREATE INDEX IF NOT EXISTS idx_cctv_devices_status  ON cctv_devices(status);
CREATE INDEX IF NOT EXISTS idx_cctv_telemetry_cctv  ON cctv_telemetry(cctv_id);
CREATE INDEX IF NOT EXISTS idx_cctv_telemetry_ts    ON cctv_telemetry(timestamp);
CREATE INDEX IF NOT EXISTS idx_aws_instances_id     ON aws_instances(instance_id);
CREATE INDEX IF NOT EXISTS idx_aws_instances_region ON aws_instances(region);
CREATE INDEX IF NOT EXISTS idx_aws_instances_state  ON aws_instances(state);
CREATE INDEX IF NOT EXISTS idx_aws_metrics_instance ON aws_metrics(instance_id);
CREATE INDEX IF NOT EXISTS idx_aws_metrics_ts       ON aws_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_fw_blocked_domain    ON firewall_blocked_domains(normalized_domain);
CREATE INDEX IF NOT EXISTS idx_fw_blocked_active    ON firewall_blocked_domains(is_active);
CREATE INDEX IF NOT EXISTS idx_fw_logs_device       ON firewall_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_fw_logs_domain       ON firewall_logs(domain);
CREATE INDEX IF NOT EXISTS idx_fw_logs_ts           ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_fw_logs_action       ON firewall_logs(action);
-- High-throughput composite query indexes
CREATE INDEX IF NOT EXISTS idx_telemetry_device_ts  ON telemetry(device_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_device_ts       ON logs(device_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_commands_device_stat ON commands(device_id, status);
CREATE INDEX IF NOT EXISTS idx_fw_logs_device_ts    ON firewall_logs(device_id, timestamp);
"""

# Migration alter statements (safe — ignores if column already present)
_ALTER_SQL = [
    "ALTER TABLE telemetry ADD COLUMN details TEXT;",
    "ALTER TABLE telemetry ADD COLUMN memory_total_gb REAL;",
    "ALTER TABLE telemetry ADD COLUMN memory_used_gb REAL;",
    "ALTER TABLE telemetry ADD COLUMN disk_total_gb REAL;",
    "ALTER TABLE telemetry ADD COLUMN disk_free_gb REAL;",
    "ALTER TABLE telemetry ADD COLUMN network_bytes_sent_mb REAL;",
    "ALTER TABLE telemetry ADD COLUMN network_bytes_recv_mb REAL;",
    "ALTER TABLE devices ADD COLUMN host_details TEXT;",
    "ALTER TABLE logs ADD COLUMN device_type TEXT;",
    "ALTER TABLE logs ADD COLUMN severity TEXT DEFAULT 'INFO';",
    "ALTER TABLE logs ADD COLUMN category TEXT DEFAULT 'OTHER';",
    "ALTER TABLE logs ADD COLUMN application_name TEXT;",
    "ALTER TABLE logs ADD COLUMN details TEXT;",
    "ALTER TABLE logs ADD COLUMN created_at TEXT DEFAULT (datetime('now'));",
]


# ── Connection Helper ────────────────────────────────────────────────

def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Return a new SQLite connection with foreign keys and WAL mode enabled."""
    path = db_path or config.DB_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row
    return conn


# ── Initialization ───────────────────────────────────────────────────

def init_database(db_path: str | None = None) -> None:
    """
    Create the database file and all tables/indexes if they do not exist.

    Safe to call repeatedly — uses CREATE TABLE IF NOT EXISTS.
    Never destroys existing data.
    """
    path = db_path or config.DB_PATH
    db_dir = Path(path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    conn = get_connection(path)
    try:
        conn.executescript(_TABLES_SQL)

        # Add new columns to existing tables if needed (safe — ignores if present)
        for stmt in _ALTER_SQL:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

        # Create indexes after tables and columns are guaranteed to exist
        conn.executescript(_INDEXES_SQL)

        conn.commit()
        logger.info("Database initialized successfully at %s", path)
    finally:
        conn.close()


# ── Health Check ─────────────────────────────────────────────────────

def check_database_health(db_path: str | None = None) -> dict:
    """Run a lightweight health check and return a status dict."""
    path = db_path or config.DB_PATH
    result = {"ok": False, "tables": [], "error": None}

    if not Path(path).exists():
        result["error"] = "Database file does not exist."
        return result

    try:
        conn = get_connection(path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        result["tables"] = [row["name"] for row in cursor.fetchall()]
        # Quick integrity check
        conn.execute("PRAGMA integrity_check;")
        result["ok"] = True
        conn.close()
    except Exception as exc:
        result["error"] = str(exc)

    return result
