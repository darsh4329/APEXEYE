"""
APEXEYE — AWS Cloud / EC2 Read-Only Monitoring Test Suite

Comprehensive tests validating:
  1. Credential mode handling (Environment provider vs Access Key + Secret Key).
  2. In-memory secret isolation (secrets never written to SQLite, logs, or API responses).
  3. Connection testing (valid credentials, invalid credentials, AccessDenied, network failure).
  4. Permission validation uses ec2:DescribeInstances (NOT ec2:DescribeRegions).
  5. EC2 Discovery with pagination, multiple instances, running and stopped instances.
  6. EC2 Status checks (system check passed/failed, instance check passed/failed).
  7. CloudWatch metrics retrieval (CPU, Network In/Out, missing metrics, throttling).
  8. Strict RAM policy: RAM is strictly N/A and NEVER fabricated.
  9. Deterministic operational anomaly detection.
 10. Security boundary: loopback-only access (@require_admin) and input sanitization.
 11. Unconfigured startup resilience: zero credentials causes no crashes or errors.
 12. Safe report builder extension.

All AWS SDK calls are mocked. Live AWS credentials are NOT required.
"""

import json
import sqlite3
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
)

import sys
from pathlib import Path
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from master.app.api import create_app
from master.app.database import get_connection, init_database
from master.app.services.aws_service import (
    AWSService,
    AWSConnectionService,
    AWSDiscoveryService,
    AWSMetricsService,
    AWSAnomalyDetector,
    aws_service,
)
from master.app.services.report_data_builder import ReportDataBuilder


@pytest.fixture(autouse=True)
def setup_aws_database():
    """Reset database and AWS service state before each test."""
    init_database()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM aws_metrics;")
        conn.execute("DELETE FROM aws_instances;")
        conn.execute("DELETE FROM aws_config;")
        conn.commit()
    finally:
        conn.close()

    # Reset in-memory AWS service singleton
    aws_service.update_config(credential_mode="env", region="us-east-1")
    with aws_service.connection._lock:
        aws_service.connection._account_id = None
        aws_service.connection._connection_status = "Not Configured"
        aws_service.connection._last_tested_at = None
        aws_service.connection._last_error = None
        aws_service.connection._access_key_id = None
        aws_service.connection._secret_access_key = None


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# ── 1. Credential Modes & In-Memory Secret Isolation ─────────────────

def test_credential_mode_env():
    """Verify Environment mode configuration and state."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(credential_mode="env", region="us-west-2")
    state = conn_svc.get_public_state()

    assert state["credential_mode"] == "env"
    assert state["region"] == "us-west-2"
    assert state["has_key_id"] is False
    assert state["has_secret"] is False


def test_credential_mode_keys_and_secret_isolation():
    """Verify Access Key mode holds secret in memory and never writes it to SQLite."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(
        credential_mode="keys",
        region="ap-south-1",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    state = conn_svc.get_public_state()

    assert state["credential_mode"] == "keys"
    assert state["region"] == "ap-south-1"
    assert state["has_key_id"] is True
    assert state["has_secret"] is True
    # Secret itself is never in public state
    assert "secret_access_key" not in state
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(state)

    # Persist via AWSService and verify SQLite contains ZERO secret keys
    aws_service.update_config(
        credential_mode="keys",
        region="ap-south-1",
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    db_conn = get_connection()
    try:
        row = db_conn.execute("SELECT * FROM aws_config ORDER BY id DESC LIMIT 1;").fetchone()
        assert row is not None
        row_dict = dict(row)
        assert row_dict["credential_mode"] == "keys"
        assert row_dict["region"] == "ap-south-1"
        assert "secret_access_key" not in row_dict
        # Verify whole row values contain no secret
        for val in row_dict.values():
            assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(val)
    finally:
        db_conn.close()


# ── 2. Connection Testing & Permission Validation ────────────────────

def test_connection_success():
    """Valid credentials successfully authenticate and verify STS, EC2, CloudWatch."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(credential_mode="env", region="us-east-1")

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    mock_cw = MagicMock()
    mock_cw.list_metrics.return_value = {"Metrics": []}

    def client_factory(service_name, **kwargs):
        if service_name == "sts":
            return mock_sts
        elif service_name == "ec2":
            return mock_ec2
        elif service_name == "cloudwatch":
            return mock_cw
        raise ValueError(f"Unexpected service: {service_name}")

    mock_session.client.side_effect = client_factory

    with patch.object(conn_svc, "create_session", return_value=mock_session):
        report = conn_svc.test_connection()

    assert report["connection_status"] == "Connected"
    assert report["account_id"] == "123456789012"
    assert report["ec2_access"] is True
    assert report["cloudwatch_access"] is True
    assert len(report["errors"]) == 0

    # Ensure ec2.describe_instances was used to validate EC2 (and NOT describe_regions)
    mock_ec2.describe_instances.assert_called_once_with(MaxResults=5)
    assert not hasattr(mock_ec2, "describe_regions") or mock_ec2.describe_regions.call_count == 0


def test_connection_invalid_credentials_auth_failure():
    """Invalid credentials return Authentication Failed status without crashing."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(credential_mode="env", region="us-east-1")

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = NoCredentialsError()
    mock_session.client.return_value = mock_sts

    with patch.object(conn_svc, "create_session", return_value=mock_session):
        report = conn_svc.test_connection()

    assert report["connection_status"] == "Authentication Failed"
    assert report["account_id"] is None
    assert report["ec2_access"] is False
    assert len(report["errors"]) > 0
    assert "No AWS credentials found" in report["errors"][0]


def test_connection_permission_denied():
    """Missing EC2 permissions returns Permission Denied status with clear message."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(credential_mode="env", region="us-east-1")

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "999888777666"}

    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized to perform this operation."}},
        "DescribeInstances"
    )

    mock_cw = MagicMock()
    mock_cw.list_metrics.return_value = {"Metrics": []}

    def client_factory(service_name, **kwargs):
        if service_name == "sts":
            return mock_sts
        elif service_name == "ec2":
            return mock_ec2
        elif service_name == "cloudwatch":
            return mock_cw

    mock_session.client.side_effect = client_factory

    with patch.object(conn_svc, "create_session", return_value=mock_session):
        report = conn_svc.test_connection()

    assert report["connection_status"] == "Permission Denied"
    assert report["account_id"] == "999888777666"
    assert report["ec2_access"] is False
    assert report["cloudwatch_access"] is True
    assert any("EC2 read permission missing" in e for e in report["errors"])


def test_connection_network_failure():
    """Endpoint network failure returns Connection Error."""
    conn_svc = AWSConnectionService()
    conn_svc.configure(credential_mode="env", region="us-east-1")

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = EndpointConnectionError(endpoint_url="https://sts.amazonaws.com")
    mock_session.client.return_value = mock_sts

    with patch.object(conn_svc, "create_session", return_value=mock_session):
        report = conn_svc.test_connection()

    assert report["connection_status"] == "Connection Error"
    assert "Unable to connect to AWS STS endpoint" in report["errors"][0]


# ── 3. EC2 Discovery, Multiple Instances & Pagination ────────────────

def test_ec2_discovery_and_status_checks():
    """EC2 discovery extracts metadata, handles pagination, and fetches status checks."""
    discovery_svc = AWSDiscoveryService()

    mock_session = MagicMock()
    mock_ec2 = MagicMock()

    # Mock pagination with 2 pages and multiple instances
    page_1 = {
        "Reservations": [
            {
                "OwnerId": "111222333444",
                "Instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "InstanceType": "t3.medium",
                        "State": {"Name": "running"},
                        "Placement": {"AvailabilityZone": "us-east-1a"},
                        "PrivateIpAddress": "172.31.10.20",
                        "PublicIpAddress": "54.210.10.20",
                        "PlatformDetails": "Linux/UNIX",
                        "LaunchTime": datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc),
                        "Tags": [{"Key": "Name", "Value": "prod-api-server"}],
                    },
                    {
                        "InstanceId": "i-0123456789abcdef1",
                        "InstanceType": "t3.small",
                        "State": {"Name": "stopped"},
                        "Placement": {"AvailabilityZone": "us-east-1b"},
                        "PrivateIpAddress": "172.31.10.21",
                        "PublicIpAddress": None,
                        "PlatformDetails": "Linux/UNIX",
                        "LaunchTime": datetime(2026, 8, 20, 14, 30, 0, tzinfo=timezone.utc),
                        "Tags": [{"Key": "Name", "Value": "staging-db"}],
                    },
                ]
            }
        ]
    }

    page_2 = {
        "Reservations": [
            {
                "OwnerId": "111222333444",
                "Instances": [
                    {
                        "InstanceId": "i-0123456789abcdef2",
                        "InstanceType": "c5.xlarge",
                        "State": {"Name": "running"},
                        "Placement": {"AvailabilityZone": "us-east-1c"},
                        "PrivateIpAddress": "172.31.10.22",
                        "PublicIpAddress": "54.210.10.22",
                        "PlatformDetails": "Windows",
                        "LaunchTime": datetime(2026, 8, 25, 8, 0, 0, tzinfo=timezone.utc),
                        "Tags": [],
                    }
                ]
            }
        ]
    }

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [page_1, page_2]
    mock_ec2.get_paginator.return_value = mock_paginator

    # Mock status checks (system check passed, instance check failed on i-0123456789abcdef0)
    mock_ec2.describe_instance_status.return_value = {
        "InstanceStatuses": [
            {
                "InstanceId": "i-0123456789abcdef0",
                "SystemStatus": {"Status": "passed"},
                "InstanceStatus": {"Status": "failed"},
            },
            {
                "InstanceId": "i-0123456789abcdef2",
                "SystemStatus": {"Status": "passed"},
                "InstanceStatus": {"Status": "passed"},
            }
        ]
    }

    mock_session.client.return_value = mock_ec2

    instances = discovery_svc.discover_instances(mock_session, "us-east-1", "111222333444")

    assert len(instances) == 3

    # Check Instance 0
    i0 = next(i for i in instances if i["instance_id"] == "i-0123456789abcdef0")
    assert i0["name"] == "prod-api-server"
    assert i0["state"] == "running"
    assert i0["system_status"] == "passed"
    assert i0["instance_status"] == "failed"
    assert i0["private_ip"] == "172.31.10.20"
    assert i0["public_ip"] == "54.210.10.20"

    # Check Instance 1 (Stopped)
    i1 = next(i for i in instances if i["instance_id"] == "i-0123456789abcdef1")
    assert i1["name"] == "staging-db"
    assert i1["state"] == "stopped"

    # Check Instance 2 (Windows, no Name tag falls back to instance_id)
    i2 = next(i for i in instances if i["instance_id"] == "i-0123456789abcdef2")
    assert i2["name"] == "i-0123456789abcdef2"
    assert i2["platform"] == "Windows"
    assert i2["system_status"] == "passed"
    assert i2["instance_status"] == "passed"


# ── 4. CloudWatch Metrics & Strict RAM Policy ────────────────────────

def test_cloudwatch_metrics_retrieval_and_ram_na():
    """CloudWatch returns CPU/Network, and RAM is strictly reported as N/A."""
    metrics_svc = AWSMetricsService()
    mock_session = MagicMock()
    mock_cw = MagicMock()

    t_now = datetime.now(timezone.utc)
    mock_cw.get_metric_data.return_value = {
        "MetricResults": [
            {"Id": "m_cpu", "Timestamps": [t_now], "Values": [24.5]},
            {"Id": "m_net_in", "Timestamps": [t_now], "Values": [1048576.0]},
            {"Id": "m_net_out", "Timestamps": [t_now], "Values": [524288.0]},
        ]
    }
    mock_session.client.return_value = mock_cw

    res = metrics_svc.get_instance_metrics(mock_session, "us-east-1", "i-0123456789abcdef0")

    assert res["cpu"] == 24.5
    assert res["network_in"] == 1048576.0
    assert res["network_out"] == 524288.0

    # CRITICAL: RAM MUST BE STRICTLY N/A / NONE
    assert res["ram"] is None
    assert "N/A" in res["ram_status"]


def test_cloudwatch_missing_metrics_and_throttling():
    """Missing metric data points and throttling are handled gracefully."""
    metrics_svc = AWSMetricsService()
    mock_session = MagicMock()
    mock_cw = MagicMock()

    # Empty values (no data points recorded by CloudWatch)
    mock_cw.get_metric_data.return_value = {
        "MetricResults": [
            {"Id": "m_cpu", "Timestamps": [], "Values": []},
            {"Id": "m_net_in", "Timestamps": [], "Values": []},
            {"Id": "m_net_out", "Timestamps": [], "Values": []},
        ]
    }
    mock_session.client.return_value = mock_cw

    res = metrics_svc.get_instance_metrics(mock_session, "us-east-1", "i-0123456789abcdef0")
    assert res["cpu"] is None
    assert res["network_in"] is None
    assert res["network_out"] is None

    # Throttling error
    mock_cw.get_metric_data.side_effect = ClientError(
        {"Error": {"Code": "RequestThrottled", "Message": "Rate exceeded"}},
        "GetMetricData"
    )
    res_throttled = metrics_svc.get_instance_metrics(mock_session, "us-east-1", "i-0123456789abcdef0")
    assert res_throttled["cpu"] is None
    assert res_throttled["ram"] is None


# ── 5. Deterministic Operational Anomalies ────────────────────────────

def test_anomaly_detector_rules():
    """Deterministic findings trigger on CPU Critical, Status Check Failures, and Stopped states."""
    detector = AWSAnomalyDetector()

    # 1. Critical CPU (>90%) and Instance Status Check Failure
    inst_crit = {
        "instance_id": "i-0123456789abcdef0",
        "name": "critical-web",
        "state": "running",
        "system_status": "passed",
        "instance_status": "failed",
    }
    metrics_crit = {"cpu": 94.2}
    anoms = detector.evaluate_instance(inst_crit, metrics_crit)

    categories = [a["category"] for a in anoms]
    severities = [a["severity"] for a in anoms]

    assert "CPU" in categories
    assert "OS" in categories
    assert "CRITICAL" in severities

    # 2. Stopped instance
    inst_stopped = {
        "instance_id": "i-0123456789abcdef1",
        "name": "dev-box",
        "state": "stopped",
        "system_status": "unknown",
        "instance_status": "unknown",
    }
    anoms_stopped = detector.evaluate_instance(inst_stopped, {"cpu": None})
    assert any("Stopped" in a["title"] for a in anoms_stopped)


# ── 6. REST API & Loopback Security Boundary ─────────────────────────

def test_aws_api_loopback_restriction(client):
    """Remote non-loopback clients are rejected with 403 Forbidden by @require_admin."""
    # Simulate request from remote LAN client
    resp = client.get("/api/aws/status", environ_overrides={"REMOTE_ADDR": "192.168.1.150"})
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_json()["error"]

    resp_post = client.post("/api/aws/config", json={"credential_mode": "env"}, environ_overrides={"REMOTE_ADDR": "192.168.1.150"})
    assert resp_post.status_code == 403


def test_aws_api_status_unconfigured(client):
    """Localhost request to /api/aws/status succeeds and reports Not Configured."""
    resp = client.get("/api/aws/status")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["connection_status"] == "Not Configured"
    assert data["credential_mode"] == "env"
    assert data["has_secret"] is False
    assert "secret_access_key" not in data


def test_aws_api_config_validation(client):
    """API validates input and rejects malformed values."""
    # Invalid mode
    resp = client.post("/api/aws/config", json={"credential_mode": "invalid_mode"})
    assert resp.status_code == 400

    # Invalid region format
    resp2 = client.post("/api/aws/config", json={"credential_mode": "env", "region": "INVALID_REGION!!!"})
    assert resp2.status_code == 400

    # Valid config
    resp3 = client.post("/api/aws/config", json={"credential_mode": "keys", "region": "ap-south-1", "access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "mysecretkey"})
    assert resp3.status_code == 200
    data = resp3.get_json()
    assert data["credential_mode"] == "keys"
    assert data["region"] == "ap-south-1"
    # Never return secret key in response
    assert "mysecretkey" not in json.dumps(data)


def test_aws_api_discover_and_list(client):
    """POST /api/aws/discover discovers instances and GET /api/aws/instances lists them."""
    mock_instances = [
        {
            "instance_id": "i-0987654321fedcba0",
            "account_id": "111222333444",
            "region": "us-east-1",
            "name": "test-micro",
            "instance_type": "t2.micro",
            "state": "running",
            "availability_zone": "us-east-1a",
            "private_ip": "10.0.1.5",
            "public_ip": "54.10.1.5",
            "platform": "Linux/UNIX",
            "launch_time": "2026-08-30 12:00:00",
            "system_status": "passed",
            "instance_status": "passed",
        }
    ]

    with patch.object(aws_service.discovery, "discover_instances", return_value=mock_instances):
        disc_resp = client.post("/api/aws/discover")
        assert disc_resp.status_code == 200
        disc_data = disc_resp.get_json()
        assert disc_data["count"] == 1

    # Query instance list
    list_resp = client.get("/api/aws/instances")
    assert list_resp.status_code == 200
    instances = list_resp.get_json()
    assert len(instances) == 1
    assert instances[0]["instance_id"] == "i-0987654321fedcba0"
    assert instances[0]["name"] == "test-micro"

    # Query single instance detail
    detail_resp = client.get("/api/aws/instances/i-0987654321fedcba0")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.get_json()
    assert detail_data["instance"]["name"] == "test-micro"
    assert "metrics" in detail_data
    assert "anomalies" in detail_data


def test_aws_report_data_builder_extension():
    """ReportDataBuilder includes AWS EC2 data safely without breaking existing structures."""
    builder = ReportDataBuilder()

    # Seed an AWS instance into the DB
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO aws_instances
               (instance_id, account_id, region, name, instance_type, state, availability_zone)
               VALUES ('i-test123456789012', '123456789012', 'us-east-1', 'ReportTest', 't3.nano', 'running', 'us-east-1a');"""
        )
        conn.commit()
    finally:
        conn.close()

    aws_data = builder.build_aws_data()
    assert aws_data["source"] == "AWS EC2"
    assert aws_data["instance_count"] >= 1
    assert any(i["instance_id"] == "i-test123456789012" for i in aws_data["instances"])

    # Full system data includes aws_cloud alongside local devices & cctv_devices
    system_data = builder.build_system_data()
    assert "aws_cloud" in system_data
    assert "cctv_devices" in system_data
    assert "devices" in system_data
