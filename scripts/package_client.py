"""
APEXEYE — Client Packaging Utility

Builds a clean, production-ready client.zip distribution archive.
Includes:
  - client/.env (configured with automatic LAN discovery by default, or explicit override if supplied)
  - client/.env.example
  - client/main.py
  - client/requirements.txt
  - client/app/...
Excludes:
  - __pycache__
  - *.pyc, *.pyo, *.log, .credentials.json, .apexeye_master_cache.json
"""

import os
import zipfile
from pathlib import Path


def package_client(master_url: str = "") -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    client_dir = repo_root / "client"
    zip_path = repo_root / "client.zip"

    # Write client/.env with optional explicit override or automatic LAN discovery default
    client_env = client_dir / ".env"
    override_line = f"APEXEYE_MASTER_URL={master_url}\n" if master_url else "# APEXEYE_MASTER_URL= (Unset = Automatic LAN Discovery)\nAPEXEYE_MASTER_URL=\n"
    client_env.write_text(
        f"# APEXEYE CLIENT CONFIGURATION\n"
        f"# Automatic Master LAN discovery (UDP 9101) is active by default.\n"
        f"{override_line}"
        f"APEXEYE_CLIENT_ID=\n"
        f"APEXEYE_CLIENT_UI_PORT=9200\n"
        f"APEXEYE_CLIENT_LOG_PATH=logs\n"
        f"APEXEYE_CLIENT_LOG_LEVEL=DEBUG\n"
        f"APEXEYE_HEARTBEAT_INTERVAL_SECONDS=3\n"
        f"APEXEYE_CLIENT_TELEMETRY_INTERVAL_SECONDS=10\n"
        f"APEXEYE_EVENT_SCAN_INTERVAL_SECONDS=5\n"
        f"APEXEYE_HOST_INFO_INTERVAL_SECONDS=300\n",
        encoding="utf-8",
    )

    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(client_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__" and not d.endswith(".egg-info")]
            for file in sorted(files):
                if (
                    file.endswith(".pyc")
                    or file.endswith(".pyo")
                    or file.endswith(".log")
                    or file == ".credentials.json"
                    or file == ".apexeye_master_cache.json"
                ):
                    continue
                file_p = Path(root) / file
                rel_p = file_p.relative_to(repo_root)
                zf.write(file_p, str(rel_p).replace("\\", "/"))

    print(f"Successfully packaged {zip_path.name} ({zip_path.stat().st_size} bytes)")
    return zip_path


if __name__ == "__main__":
    package_client()
