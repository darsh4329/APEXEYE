"""
APEXEYE MASTER — Data Models

Lightweight data classes representing database entities.
These are NOT ORM models; they are used for type hints and data transfer.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Device:
    device_id: str
    device_name: str
    device_type: str  # WINDOWS_PC | LINUX_PC | CCTV | AWS_INSTANCE | OTHER
    operating_system: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    status: str = "inactive"
    authentication_status: str = "unauthenticated"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_seen: Optional[str] = None
    id: Optional[int] = None


@dataclass
class DeviceAuth:
    device_id: str
    credential_id: str
    authentication_status: str = "pending"
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    id: Optional[int] = None


@dataclass
class TelemetryRecord:
    device_id: str
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_usage: Optional[float] = None
    health_score: Optional[float] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None


@dataclass
class LogEntry:
    level: str
    device_id: Optional[str] = None
    event_type: Optional[str] = None
    message: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Alert:
    severity: str
    alert_type: str
    device_id: Optional[str] = None
    message: Optional[str] = None
    status: str = "open"
    acknowledged_at: Optional[str] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None


@dataclass
class AuditLog:
    actor: str
    action: str
    target: Optional[str] = None
    details: Optional[str] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Report:
    report_type: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    file_path: Optional[str] = None
    status: str = "pending"
    generated_at: Optional[str] = None
    id: Optional[int] = None
