# APEXEYE

<div align="center">

**Enterprise-Grade Centralized Endpoint & Infrastructure Monitoring Platform**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/)
[![Architecture](https://img.shields.io/badge/architecture-Master%20%2F%20Client-orange.svg)](https://github.com/)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](https://github.com/)

</div>

---

## Table of Contents

- [Overview](#overview)
- [System Previews](#system-previews)
- [Core Features](#core-features)
- [Architecture & Data Flow](#architecture--data-flow)
- [Technology Stack](#technology-stack)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration (.env)](#configuration-env)
  - [Running Master Server](#running-master-server)
  - [Running Client Agent](#running-client-agent)
- [Pairing & Enrollment](#pairing--enrollment)
- [Network & Deployment Topologies](#network--deployment-topologies)
- [Security & Policy Enforcement](#security--policy-enforcement)
- [REST API Reference](#rest-api-reference)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [License](#license)

---

## Overview

**APEXEYE** is a robust, full-stack infrastructure telemetry and endpoint management platform engineered for hybrid environments. Operating on a high-resilience **Master / Distributed Agent** model, APEXEYE unifies real-time system metrics, automated heartbeat lifecycle monitoring, hardware diagnostics, centralized log streaming, network firewall policy enforcement, CCTV/RTSP camera health inspection, AWS cloud monitoring, and AI-driven root-cause incident analysis into a single, intuitive command center.

Designed with zero-trust networking principles, client agents communicate strictly over authenticated REST endpoints and never touch internal database layers directly.

---

## System Previews

### 1. Master Command Center & Fleet Dashboard

<img width="1911" height="941" alt="Screenshot 2026-09-15 212528" src="https://github.com/user-attachments/assets/66580ed6-32ae-452e-bac9-d2669660f2a9" />

<img width="1874" height="873" alt="Screenshot 2026-09-15 212608" src="https://github.com/user-attachments/assets/34e10d65-3c59-47ef-8bc2-dc161702158e" />

---

*Master web dashboard visualizing real-time fleet telemetry, connected endpoints, live status gauges, and anomaly alerts.*

---

### 2. Client Agent Dashboard
<!-- Placeholder: Basic screenshot of Client Dashboard -->
```
+-----------------------------------------------------------------------------------+
|                                                                                   |
|                   [ SCREENSHOT PLACEHOLDER: CLIENT DASHBOARD ]                    |
|             (Local Enrollment, Active Heartbeat, Agent Metrics, Master Link)      |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```
*Client agent local web interface running on port 9200 for token pairing, host resource metrics, and sync state.*

---

### 3. Network Firewall & Policy Manager

<img width="1880" height="873" alt="Screenshot 2026-09-15 212635" src="https://github.com/user-attachments/assets/443f0f8f-e9bd-477b-91cf-f1befa595659" />

<img width="1852" height="877" alt="Screenshot 2026-09-15 212650" src="https://github.com/user-attachments/assets/fb0477a0-7341-47bf-b179-b99dc82e8ecc" />


```
*Firewall policy editor and security enforcement panel controlling domain blacklists, IP rules, and custom block pages.*

---

### 4. Centralized System & Audit Logs

<img width="1852" height="877" alt="Screenshot 2026-09-15 212650" src="https://github.com/user-attachments/assets/39e45901-f99a-4d57-9170-a6141c20da71" />

```
*Centralized event log viewer with real-time log ingestion, severity filtering (INFO, WARN, ERROR, CRITICAL), and tamper-evident audit logs.*

---

## Core Features

- ⚡ **Real-Time Fleet Telemetry**: Tracks CPU utilization, multi-core loads, RAM allocation, disk read/write bandwidth, file system partitions, and network I/O per interface.
- 💓 **Live Heartbeat & Lifecycle State Engine**: Sub-second heartbeat pings with automated presence detection (`ONLINE`, `DEGRADED`, `OFFLINE`) and automatic state recovery.
- 🛡️ **Network Firewall & Domain Filtering**: Push-button distributed domain blocking, local hosts sinkholing, and automated redirection to custom warning pages.
- 🔍 **LAN Auto-Discovery**: Automatic Master discovery across local subnets using UDP broadcast (port 9101), eliminating manual IP configuration.
- 📜 **Centralized Log Aggregation**: Collects application events, operating system logs (Windows Event Logs / Linux Syslog), and operator audit trails into unified storage.
- 📹 **CCTV & RTSP Camera Probing**: Autonomous background monitoring of ONVIF/RTSP IP security cameras with latency tracking, packet loss indicators, and stream health status.
- ☁️ **AWS Cloud Telemetry**: Seamless integration with AWS EC2 and CloudWatch for unified cloud and on-premise observability.
- 🧠 **AI-Powered Incident Diagnosis**: Automated root-cause analysis, anomaly summarization, and remediation suggestions powered by Gemini, Ollama, Groq, or rule-based inference.
- 📊 **Automated PDF Executive Reporting**: Generates comprehensive, production-grade PDF health reports with embedded metric charts, incident histories, and compliance audits.
- 🔐 **Zero-Trust Token Authentication**: Cryptographic token-based client pairing, authenticated headers, rate limiting, and complete database isolation.

---

## Architecture & Data Flow

```
                      ┌─────────────────────────────────┐
                      │         APEXEYE MASTER          │
                      │    (Web UI & API : Port 9100)   │
                      │   (LAN UDP Discovery : Port 9101│
                      └────────────────┬────────────────┘
                                       │
                      ┌────────────────┴────────────────┐
                      │    SQLite Database (Master-Only)│
                      │       database/apexeye.db       │
                      └────────────────┬────────────────┘
                                       │
                REST API (JSON / Bearer Token Authentication)
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         ▼                             ▼                             ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  Windows Client  │          │   Linux Client   │          │ CCTV / Cloud Hub │
│ (Agent: UI 9200) │          │ (Agent: UI 9200) │          │ (RTSP / AWS EC2) │
└──────────────────┘          └──────────────────┘          └──────────────────┘
```

### Architectural Guarantees:
1. **Master Sole Custody**: Only the Master server touches `database/apexeye.db`. Clients never query or alter the database directly.
2. **Stateless REST Communication**: All metrics, heartbeats, logs, and commands traverse authenticated HTTP REST endpoints.
3. **Fault Tolerance**: Clients queue telemetry locally during network disconnection and flush metrics upon link restoration.

---

## Technology Stack

| Layer | Technologies |
|---|---|
| **Core Backend** | Python 3.10+, Flask, Threading / Multiprocessing |
| **Data Storage** | SQLite 3 (WAL mode enabled, thread-safe access) |
| **System Telemetry** | `psutil`, `socket`, `platform`, `ctypes` (Win32 API) |
| **Security & Auth** | Cryptographic token hashes, Bearer authentication, WFP / hosts sinkholing |
| **Web Dashboards** | HTML5, Vanilla CSS3 (Glassmorphic dark design), Modern ES6 JavaScript |
| **Reporting & Charts** | ReportLab, Matplotlib |
| **AI Providers** | Google Gemini API, Ollama (Local LLM), Groq, Rule-based fallback |
| **Network Protocols**| HTTP/1.1 REST, UDP Broadcast (9101), ICMP / RTSP pinging |

---

## Directory Structure

```
apexeye/
├── master/                         # MASTER SERVER APPLICATION
│   ├── app/
│   │   ├── api/                    # REST API routes, controllers & middleware
│   │   │   ├── templates/          # Master dashboard & firewall web views
│   │   │   ├── devices.py          # Device registration & management
│   │   │   ├── telemetry.py        # Telemetry ingestion endpoints
│   │   │   ├── firewall_api.py     # Firewall policy rules API
│   │   │   ├── logs_api.py         # Log collector & viewer API
│   │   │   └── ai_api.py           # AI summarization & diagnosis API
│   │   ├── auth/                   # Token issuance, hashing & verification
│   │   ├── config/                 # Master runtime configuration
│   │   ├── database/               # SQLite schema migrations & query models
│   │   ├── models/                 # Domain data models
│   │   ├── services/               # Core business services
│   │   │   ├── health_service.py   # Health scoring & evaluation
│   │   │   ├── presence_service.py # Live device presence watchdog
│   │   │   ├── firewall_service.py # Central firewall rules management
│   │   │   ├── cctv_service.py     # CCTV & RTSP camera prober
│   │   │   ├── ai_service.py       # LLM anomaly diagnosis pipeline
│   │   │   └── pdf_renderer.py     # Executive PDF report generation
│   │   └── utils/                  # Logging, networking & helper routines
│   ├── main.py                     # Master entry point
│   └── requirements.txt            # Master dependencies
│
├── client/                         # WINDOWS CLIENT AGENT
│   ├── app/
│   │   ├── agent.py                # Telemetry collection & heartbeat loop
│   │   ├── auth/                   # Client-side pairing & token handling
│   │   ├── collectors/             # CPU, RAM, Disk, Network, System collectors
│   │   ├── communication/          # HTTP REST connection to Master
│   │   ├── discovery/              # UDP LAN broadcast listener & prober
│   │   ├── services/               # Firewall enforcer, command handler, block server
│   │   ├── ui/                     # Local browser UI (port 9200) for pairing
│   │   └── utils/                  # Agent logging & diagnostics
│   ├── main.py                     # Windows Client entry point
│   └── requirements.txt            # Client dependencies
│
├── client_linux/                   # LINUX CLIENT AGENT
│   ├── app/                        # Linux-specific collectors & agent modules
│   ├── main.py                     # Linux Client entry point
│   └── requirements.txt            # Linux dependencies
│
├── database/                       # Master SQLite storage (apexeye.db)
├── logs/                           # System and diagnostic logs
├── tests/                          # Automated unit, integration & e2e test suite
├── .env.example                    # Environment variable configuration template
├── NETWORKING.md                   # Comprehensive network & deployment manual
├── LICENSE                         # MIT License
└── README.md                       # Project documentation
```

---

## Getting Started

### Prerequisites

- **Python**: Version `3.10` or higher installed.
- **Operating Systems**: 
  - Master: Windows 10/11, Windows Server, or Linux.
  - Client: Windows 10/11 (Administrator rights recommended for firewall features) or Linux (Ubuntu, Debian, RHEL).

---

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/apexeye.git
   cd apexeye
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   # Master dependencies
   pip install -r master/requirements.txt

   # Client dependencies
   pip install -r client/requirements.txt
   ```

---

### Configuration (.env)

Copy the template configuration to `.env`:

```bash
cp .env.example .env
```

Key environment parameters:

```env
# Master Server Settings
APEXEYE_ENV=development
APEXEYE_MASTER_HOST=0.0.0.0
APEXEYE_MASTER_PORT=9100
APEXEYE_DB_PATH=database/apexeye.db
APEXEYE_LOG_LEVEL=INFO

# Client Settings
APEXEYE_MASTER_URL=http://127.0.0.1:9100    # Point to Master's reachable IP
APEXEYE_CLIENT_UI_PORT=9200
APEXEYE_HEARTBEAT_INTERVAL_SECONDS=3
APEXEYE_CLIENT_TELEMETRY_INTERVAL_SECONDS=60
```

---

### Running Master Server

Start the Master server from the project root:

```bash
python -m master.main
```

Upon startup, the Master server:
1. Verifies and initializes SQLite tables in `database/apexeye.db`.
2. Starts background monitors for CCTV cameras and device presence tracking.
3. Launches the UDP discovery listener on port `9101`.
4. Spawns the web server on `http://0.0.0.0:9100`.

Open your browser to access the Master Dashboard:
```
http://127.0.0.1:9100/dashboard
```

---

### Running Client Agent

Start the client agent from the project root:

```bash
python -m client.main
```

Upon startup, the Client agent:
1. Runs UDP auto-discovery to detect the active Master on the local subnet.
2. Serves a local pairing & status portal on `http://127.0.0.1:9200`.
3. Opens the local pairing interface in your default browser if not yet enrolled.
4. Begins sending periodic telemetry and heartbeats to the Master.

---

## Pairing & Enrollment

APEXEYE provides two seamless methods to pair an agent with the Master:

1. **Web UI Pairing (Recommended)**:
   - Open `http://127.0.0.1:9200` on the client machine.
   - Enter the Device ID and enrollment token created on the Master.
   - Click **Pair Device**. The client will automatically authenticate and begin streaming telemetry.

2. **Terminal Prompt**:
   - If executed interactively in a terminal, enter the `Device ID` and `Token` directly when prompted.

---

## Network & Deployment Topologies

For complete topology diagrams and firewall configuration, refer to [NETWORKING.md](NETWORKING.md).

| Deployment Scenario | Master Configuration | Client Configuration | Description |
|---|---|---|---|
| **Local Machine (Dev/Test)** | `APEXEYE_MASTER_HOST=0.0.0.0` | `APEXEYE_MASTER_URL=http://127.0.0.1:9100` | Loopback testing on a single machine. |
| **Same Wi-Fi / LAN Subnet** | `APEXEYE_MASTER_HOST=0.0.0.0` | `APEXEYE_MASTER_URL=http://192.168.1.X:9100` | Devices connected to the same physical switch or router. |
| **Mesh VPN (Tailscale/WireGuard)** | `APEXEYE_MASTER_HOST=0.0.0.0` | `APEXEYE_MASTER_URL=http://100.X.Y.Z:9100` | Cross-network and remote endpoints via encrypted overlay network. |

---

## Security & Policy Enforcement

- **Database Isolation**: Clients have zero database drivers or credentials; all operations require Master API authentication.
- **Token Verification**: Requests are validated against SHA-256 token hashes stored securely in `device_auth`.
- **Firewall Policy Engine**:
  - Administrators create rules (block domain, block IP, allowlist) in the Master Firewall dashboard.
  - Agents fetch active policies and enforce them using host-level routing and sinkholing.
  - Blocked web traffic is smoothly redirected to a friendly block advisory page.
- **Audit Trails**: Critical operations (device approvals, rule additions, command executions) are logged to an immutable audit table.

---

## REST API Reference

The Master exposes clean, standardized REST endpoints:

### Health & Heartbeat
- `GET /health` — Check Master server and database health status.
- `POST /api/v1/heartbeat` — Ingest client heartbeat ping and update device presence.

### Devices & Telemetry
- `GET /api/v1/devices` — List all registered endpoints and current states.
- `POST /api/v1/devices/register` — Register a new device with authentication token.
- `POST /api/v1/telemetry` — Ingest system metrics batch from an agent.
- `GET /api/v1/telemetry/<device_id>/latest` — Retrieve the most recent telemetry sample for an endpoint.

### Firewall & Policies
- `GET /api/v1/firewall/rules` — Retrieve active domain and IP blocking rules.
- `POST /api/v1/firewall/rules` — Add or modify security rules.
- `DELETE /api/v1/firewall/rules/<rule_id>` — Revoke a firewall rule.

### Logs & Events
- `POST /api/v1/logs` — Ingest structured log entries from an endpoint.
- `GET /api/v1/logs` — Query and filter logs by device, severity, or keyword.

### CCTV & Infrastructure
- `GET /api/v1/cctv` — Retrieve status and latency metrics for all monitored cameras.
- `POST /api/v1/cctv` — Register a new camera or RTSP endpoint for automated polling.

### AI & Reporting
- `POST /api/v1/ai/diagnose` — Trigger AI-powered root-cause analysis for system anomalies.
- `POST /api/v1/reports/generate` — Compile and download an executive PDF telemetry report.

---

## Testing & Quality Assurance

APEXEYE includes a comprehensive suite of automated tests covering unit logic, integration pipelines, database transactions, network edge cases, and heartbeat lifecycles.

Run all tests with `pytest`:

```bash
python -m pytest tests/ -v
```

Or run individual targeted test suites:

```bash
# Verify Master and database services
python -m pytest tests/test_master.py -v

# Verify Client agent telemetry & communication
python -m pytest tests/test_client.py -v

# Verify Heartbeat presence and recovery lifecycle
python -m pytest tests/verify_heartbeat_presence_lifecycle.py -v

# Verify CCTV probing functionality
python -m pytest tests/test_cctv.py -v
```

---

## License

This project is licensed under the **MIT License**.

```text
MIT License

Copyright (c) 2026 APEXEYE Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
