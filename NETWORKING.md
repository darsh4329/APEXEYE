# APEXEYE Networking & Deployment Guide

This document explains how to configure, deploy, and troubleshoot network communication between the **APEXEYE Master** server and **APEXEYE Client** agents across different network topologies.

---

## 1. Network Architecture Overview

APEXEYE operates on a centralized **Master / Distributed Client** model:

```
                          ┌──────────────────────────┐
                          │      APEXEYE MASTER      │
                          │   (Host: 0.0.0.0:9100)   │
                          │     Sole DB Manager      │
                          └─────────────▲────────────┘
                                        │
                         HTTP REST API  │ (Port 9100)
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │                               │                               │
┌───────┴───────────────┐     ┌─────────┴─────────────┐     ┌───────────┴───────────┐
│    Windows Client 1   │     │    Windows Client 2   │     │     Linux Client 1    │
│  (Laptop / Same LAN)  │     │   (Remote over VPN)   │     │   (Server / Same LAN) │
└───────────────────────┘     └───────────────────────┘     └───────────────────────┘
```

### Architectural Principles:
1. **Client Independence**: Clients communicate **solely** through the Master HTTP REST API. Clients never access the SQLite database directly and never import Master internal modules.
2. **Master Sole Ownership**: Master is the single source of truth and the exclusive manager of `apexeye.db`.
3. **No Blind Public Exposure**: Master listens on local network interfaces. Access across networks is mediated through firewalls, local subnets, or secure overlay VPNs.

---

## 2. Master Server Configuration

The Master server must listen on a network interface accessible to clients.

In `.env` (or environment variables) on the **Master machine**:

```env
# Master binds to all local network interfaces (0.0.0.0)
APEXEYE_MASTER_HOST=0.0.0.0

# Master HTTP port
APEXEYE_MASTER_PORT=9100
```

> **Note on `0.0.0.0`**: Binding to `0.0.0.0` instructs the operating system that the Master server listens on **all available local network interfaces** (loopback, Ethernet, Wi-Fi, VPN adapters). It does **not** automatically expose the server to the public Internet; actual reachability is strictly determined by host firewalls, local subnet routing, NAT gateways, and VPNs.

---

## 3. Client Configuration

Clients must be configured with the reachable Master URL.

In `.env` (or environment variables) on each **Client machine**:

```env
# Full URL to reach the Master API
APEXEYE_MASTER_URL=http://<MASTER-IP-OR-HOSTNAME>:9100
```

### Precedence:
1. `APEXEYE_MASTER_URL` (Recommended) — Full URL including protocol and port.
2. `APEXEYE_MASTER_ADDRESS` + `APEXEYE_MASTER_SERVER_PORT` (Legacy fallback).

---

## 4. Deployment Scenarios & Examples

### Scenario A: Same Computer (Development / Local Testing)
Both Master and Client run on the same physical machine.

- **Master Config**:
  ```env
  APEXEYE_MASTER_HOST=0.0.0.0   # or 127.0.0.1
  APEXEYE_MASTER_PORT=9100
  ```
- **Client Config**:
  ```env
  APEXEYE_MASTER_URL=http://127.0.0.1:9100
  ```
- **Reachability**: Works immediately via local loopback interface.

---

### Scenario B: Same Wi-Fi / Local Area Network (Two Laptops / PCs)
Master is running on Laptop A, and Client is running on Laptop B connected to the same Wi-Fi router or Ethernet switch.

1. **Find Master's Local IP** on Laptop A:
   - Run: `python -m master.main`
   - Master automatically discovers and prints its primary physical LAN IP (e.g. `10.177.134.109` or `192.168.1.25`) in the startup banner.
   - Alternatively, inspect `ipconfig` in PowerShell:
     - Look for the active **Wi-Fi** or **Physical Ethernet** adapter.
     - **CRITICAL**: Ignore VirtualBox Host-Only (`192.168.56.1`), VMware, Docker, or Link-Local (`169.254.x.x`) adapters!

2. **Master Config (Laptop A)**:
   ```env
   APEXEYE_MASTER_HOST=0.0.0.0
   APEXEYE_MASTER_PORT=9100
   ```

3. **Client Config (Laptop B)**:
   ```env
   APEXEYE_MASTER_URL=http://10.177.134.109:9100
   ```
   *(Replace `10.177.134.109` with Master's actual Wi-Fi IPv4 address. NEVER use `127.0.0.1` on Laptop B!)*

4. **Firewall Requirement**:
   Laptop A's Windows Defender Firewall will block incoming connections on port 9100 by default. You **must** allow port 9100 inbound (see Section 6 below).

---

### Scenario C: Different Networks (Home vs Office / Remote / Mobile)
Master is on one network (e.g., Home Wi-Fi) and Client is on a separate network (e.g., Mobile Hotspot, Office Wi-Fi, Cloud).

#### Why Direct IP Does Not Work Across Different Networks:
- Machines behind consumer or enterprise routers receive private IP addresses (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`) that are **not routable** over the public Internet.
- NAT (Network Address Translation) and router firewalls block unsolicited inbound traffic from external networks.
- Traditional port-forwarding on home routers requires public IPv4, manual router reconfiguration, and exposes ports directly to public scanning.

#### Recommended Safe Solution: Overlay Network / VPN
Use a secure mesh overlay VPN such as **Tailscale**, **WireGuard**, or **ZeroTier**.

1. Install Tailscale (or WireGuard) on both the Master machine and Client machine.
2. Both machines receive a secure, encrypted private IP on the virtual overlay network (e.g., `100.85.12.34`).
3. **Master Config**:
   ```env
   APEXEYE_MASTER_HOST=0.0.0.0
   APEXEYE_MASTER_PORT=9100
   ```
4. **Client Config**:
   ```env
   APEXEYE_MASTER_URL=http://100.85.12.34:9100
   ```
5. **Benefits**:
   - Zero port-forwarding required.
   - End-to-end encrypted peer-to-peer traffic.
   - NAT traversal handled automatically.
   - Works regardless of Wi-Fi changes, roaming, or firewalls.

---

## 5. Authoritative Health Check & Diagnostics

### Health Check Endpoint
The Master provides an unauthenticated health check endpoint:
```http
GET /api/health
```

Example response:
```json
{
  "status": "healthy",
  "app": "APEXEYE Master",
  "version": "0.1.0",
  "timestamp": "2026-08-25 10:00:00",
  "bind_address": "0.0.0.0:9100"
}
```

### Authoritative Verification:
Do not rely on `ping` as definitive proof of reachability, because many firewalls drop ICMP echo requests while allowing TCP port 9100.

To test Master reachability from a Client machine, run:
```bash
# Windows PowerShell
Invoke-RestMethod -Uri http://<MASTER-IP>:9100/api/health

# Linux / macOS / Git Bash / curl
curl -i http://<MASTER-IP>:9100/api/health
```

When the Client starts, it automatically performs this health check and displays:
```
============================================================
Master reachable : YES
Master URL       : http://192.168.1.45:9100
API status       : healthy
Master version   : 0.1.0
============================================================
```

If unreachable, it presents structured diagnostics detailing exact troubleshooting steps without crashing with raw tracebacks.

---

## 6. Windows Defender Firewall Configuration

If the Master is on Windows, Windows Firewall will block incoming connections on port 9100 from other computers on the LAN.

> **DO NOT disable Windows Firewall globally.** Only allow the specific TCP port 9100.

### Adding the Inbound Rule (Run in PowerShell as Administrator on Master Machine):
```powershell
New-NetFirewallRule -DisplayName "APEXEYE Master API (Port 9100)" `
                    -Direction Inbound `
                    -LocalPort 9100 `
                    -Protocol TCP `
                    -Action Allow `
                    -Profile Private, Domain
```

### Verifying the Rule:
```powershell
Get-NetFirewallRule -DisplayName "APEXEYE Master API (Port 9100)" | Format-Table Name, DisplayName, Enabled, Direction, Action
```

### Removing the Rule (if ever needed):
```powershell
Remove-NetFirewallRule -DisplayName "APEXEYE Master API (Port 9100)"
```

---

## 7. Authentication Integrity

Networking configuration changes **do not weaken or bypass** security:

- **Self-Registration & Pairing**: Unauthenticated clients cannot submit telemetry or execute operations.
- **Token Verification**: Tokens are securely hashed with SHA-256 before database storage.
- **Header Authentication**: Subsequent requests must include valid `X-Device-ID` and `X-Auth-Token` headers.
- **Credential Storage**: Clients store tokens in obfuscated format on disk, never in plaintext.
- **Audit Logging**: All authentication attempts (successful or failed) are recorded in `audit_logs`.
