"""
APEXEYE CLIENT — Collectors Package (Phase 2)

Exports all telemetry and event collectors.
"""

from client.app.collectors.cpu import CPUCollector
from client.app.collectors.memory import MemoryCollector
from client.app.collectors.disk import DiskCollector
from client.app.collectors.network import NetworkCollector
from client.app.collectors.os_info import OSInfoCollector
from client.app.collectors.events import EventCollector

__all__ = [
    "CPUCollector",
    "MemoryCollector",
    "DiskCollector",
    "NetworkCollector",
    "OSInfoCollector",
    "EventCollector",
]
