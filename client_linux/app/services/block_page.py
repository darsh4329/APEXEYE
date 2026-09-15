"""
APEXEYE LINUX CLIENT — Branded Blocked Page Generator (Linux Parity)

Renders a dedicated, security-gateway "Access Blocked" page inspired by enterprise
firewall appliances (Fortinet/Palo Alto) with distinct APEXEYE cybersecurity branding.

Security invariants:
- All dynamic inputs (host, URL, client_id, reason) are strictly HTML-escaped to prevent XSS.
- Sensitive internal paths, credentials, and tokens are never exposed in the response.
"""

import html
from datetime import datetime, timezone
from typing import Optional

from client_linux.app.utils.timezone import utc_to_local_display


def render_block_page(
    domain: str,
    url: str = "",
    reason: str = "Blocked by firewall policy",
    client_id: str = "",
    policy_version: int = 0,
    timestamp: Optional[str] = None,
) -> str:
    """
    Generate the branded APEXEYE Access Blocked HTML response.
    All inputs are sanitized and HTML-escaped.
    """
    safe_domain = html.escape(domain or "Unknown Domain")
    safe_url = html.escape(url or f"http://{safe_domain}/")
    safe_reason = html.escape(reason or "Blocked by firewall policy")
    safe_client = html.escape(client_id or "APEXEYE-ENDPOINT")
    safe_version = html.escape(str(policy_version))
    safe_time = html.escape(timestamp or utc_to_local_display(datetime.now(timezone.utc)))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>APEXEYE — Access Blocked</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        :root {{
            --bg: #07090e;
            --surface: rgba(15, 23, 42, 0.88);
            --border: rgba(59, 130, 246, 0.22);
            --border-red: rgba(239, 68, 68, 0.35);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --primary: #00e5ff;
            --primary-glow: rgba(0, 229, 255, 0.2);
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.25);
            --danger-bg: rgba(239, 68, 68, 0.12);
        }}
        body {{
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 50% 10%, rgba(239, 68, 68, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 10% 90%, rgba(0, 229, 255, 0.04) 0%, transparent 45%);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            line-height: 1.5;
        }}
        .gateway-card {{
            width: 100%;
            max-width: 680px;
            background: var(--surface);
            border: 1px solid var(--border-red);
            border-radius: 18px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 35px var(--danger-glow);
            overflow: hidden;
            backdrop-filter: blur(16px);
            animation: fadeIn 0.35s ease-out;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(12px) scale(0.98); }}
            to {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}
        .card-topbar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 28px;
            background: linear-gradient(90deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.4) 100%);
            border-bottom: 1px solid var(--border);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-logo {{
            width: 34px;
            height: 34px;
            background: linear-gradient(135deg, var(--danger), #b91c1c);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            font-weight: 800;
            color: #fff;
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
        }}
        .brand-text {{
            font-size: 17px;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: #fff;
        }}
        .brand-text span {{
            color: var(--primary);
        }}
        .status-pill {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--danger-bg);
            border: 1px solid var(--danger);
            color: #fca5a5;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 4px 12px;
            border-radius: 999px;
        }}
        .pulse-circle {{
            width: 7px;
            height: 7px;
            background: var(--danger);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--danger);
        }}
        .card-body {{
            padding: 32px 36px;
        }}
        .alert-header {{
            display: flex;
            align-items: flex-start;
            gap: 20px;
            margin-bottom: 26px;
        }}
        .alert-icon-box {{
            width: 56px;
            height: 56px;
            border-radius: 14px;
            background: var(--danger-bg);
            border: 1px solid var(--danger);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            color: var(--danger);
            flex-shrink: 0;
            box-shadow: 0 0 20px var(--danger-glow);
        }}
        .alert-title-wrap h1 {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #fff;
            margin-bottom: 6px;
        }}
        .alert-title-wrap p {{
            font-size: 14px;
            color: var(--text-secondary);
        }}
        .details-table {{
            width: 100%;
            background: rgba(10, 15, 26, 0.7);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        .detail-row {{
            display: flex;
            padding: 12px 18px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 13px;
        }}
        .detail-row:last-child {{
            border-bottom: none;
        }}
        .detail-label {{
            width: 130px;
            flex-shrink: 0;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
        }}
        .detail-val {{
            flex: 1;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
        }}
        .detail-val.highlight {{
            color: #fca5a5;
            font-weight: 600;
        }}
        .card-footer {{
            padding-top: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.06);
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-muted);
            flex-wrap: wrap;
            gap: 10px;
        }}
        .footer-brand {{
            color: var(--text-secondary);
            font-weight: 500;
        }}
    </style>
</head>
<body>
    <div class="gateway-card" id="apexeye-block-card">
        <div class="card-topbar">
            <div class="brand">
                <div class="brand-logo">A</div>
                <div class="brand-text">APEX<span>EYE</span> FIREWALL</div>
            </div>
            <div class="status-pill">
                <div class="pulse-circle"></div>
                ACCESS BLOCKED
            </div>
        </div>
        <div class="card-body">
            <div class="alert-header">
                <div class="alert-icon-box">🛡️</div>
                <div class="alert-title-wrap">
                    <h1>Website Blocked</h1>
                    <p>Access to this destination has been restricted by APEXEYE Endpoint Security policy.</p>
                </div>
            </div>

            <div class="details-table">
                <div class="detail-row">
                    <div class="detail-label">Requested Domain</div>
                    <div class="detail-val highlight" id="blocked-domain">{safe_domain}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Requested URL</div>
                    <div class="detail-val" id="blocked-url">{safe_url}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Block Reason</div>
                    <div class="detail-val" id="blocked-reason">{safe_reason}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Client Device</div>
                    <div class="detail-val" id="client-device">{safe_client}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Policy Version</div>
                    <div class="detail-val" id="policy-version">v{safe_version}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Timestamp</div>
                    <div class="detail-val" id="blocked-timestamp">{safe_time}</div>
                </div>
            </div>

            <div class="card-footer">
                <div class="footer-brand">APEXEYE Endpoint Security Gateway</div>
                <div>If you believe this is an error, contact your system administrator.</div>
            </div>
        </div>
    </div>
</body>
</html>"""


__all__ = ["render_block_page"]
