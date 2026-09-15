"""
Investigate OPT-1: Collector memory footprint and statefulness.
"""
import sys
import psutil
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from client.app.collectors.cpu import CPUCollector
from client.app.collectors.memory import MemoryCollector
from client.app.collectors.disk import DiskCollector
from client.app.collectors.network import NetworkCollector
from client.app.collectors.os_info import OSInfoCollector

def check_collectors():
    cpu = CPUCollector()
    mem = MemoryCollector()
    disk = DiskCollector()
    net = NetworkCollector()
    osi = OSInfoCollector()

    print("--- Collector Object Sizes ---")
    print(f"CPUCollector:    {sys.getsizeof(cpu)} bytes (dict: {sys.getsizeof(cpu.__dict__)})")
    print(f"MemoryCollector: {sys.getsizeof(mem)} bytes (dict: {sys.getsizeof(mem.__dict__)})")
    print(f"DiskCollector:   {sys.getsizeof(disk)} bytes (dict: {sys.getsizeof(disk.__dict__)})")
    print(f"NetworkCollector:{sys.getsizeof(net)} bytes (dict: {sys.getsizeof(net.__dict__)})")
    print(f"OSInfoCollector: {sys.getsizeof(osi)} bytes (dict: {sys.getsizeof(osi.__dict__)})")

    # Check CPUCollector statefulness
    print("\n--- CPUCollector Statefulness Check ---")
    s1 = cpu.collect()
    print(f"Sample 1 CPU usage: {s1.get('cpu_usage')}%")
    # Calling psutil.cpu_percent directly
    p1 = psutil.cpu_percent(interval=None)
    s2 = cpu.collect()
    print(f"Intervening psutil call: {p1}%")
    print(f"Sample 2 CPU usage immediately after: {s2.get('cpu_usage')}%")

if __name__ == "__main__":
    check_collectors()
