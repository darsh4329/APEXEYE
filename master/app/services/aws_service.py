"""
APEXEYE MASTER — AWS Cloud / EC2 Read-Only Monitoring Service

Provides read-only monitoring integration with Amazon EC2 and CloudWatch.
Architecture:
  - AWSConnectionService: Credentials, sessions, STS caller identity, permissions testing.
  - AWSDiscoveryService: EC2 instance discovery, pagination, metadata, status checks.
  - AWSMetricsService: CloudWatch GetMetricData batch queries, missing metric handling.
  - AWSAnomalyDetector: Deterministic operational anomaly detection.
  - AWSService: Central coordinator facade.

Rules:
  - Strictly READ-ONLY. No instance control (start/stop/reboot/terminate).
  - AWS instances are remote cloud resources (distinct from local agents).
  - Secret keys are held in memory/runtime only, never logged, persisted, or leaked.
  - RAM is NEVER fabricated. Standard EC2 CloudWatch reports RAM as N/A.
"""

import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from master.app.database import get_connection
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.aws")

try:
    import boto3
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        ParamValidationError,
    )
    BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception
    EndpointConnectionError = Exception
    NoCredentialsError = Exception
    ParamValidationError = Exception
    BOTO3_AVAILABLE = False


# Supported standard AWS regions
AWS_STANDARD_REGIONS = [
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ca-central-1",
    "sa-east-1",
]


class AWSConnectionService:
    """Manages AWS sessions, credentials, and connection testing."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._credential_mode: str = "env"  # "env" or "keys"
        self._region: str = "us-east-1"
        self._access_key_id: Optional[str] = None
        self._secret_access_key: Optional[str] = None  # Held in memory only
        self._account_id: Optional[str] = None
        self._connection_status: str = "Not Configured"
        self._last_tested_at: Optional[str] = None
        self._last_error: Optional[str] = None

    def configure(
        self,
        credential_mode: str,
        region: str,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
    ) -> None:
        """Update runtime credential configuration."""
        with self._lock:
            self._credential_mode = credential_mode if credential_mode in ("env", "keys") else "env"
            if region and region.strip():
                self._region = region.strip()
            if self._credential_mode == "keys":
                if access_key_id is not None:
                    self._access_key_id = access_key_id.strip() or None
                if secret_access_key is not None:
                    # Only overwrite secret if a non-empty value was provided
                    if secret_access_key.strip():
                        self._secret_access_key = secret_access_key.strip()
            else:
                self._access_key_id = None
                self._secret_access_key = None

    def create_session(self) -> Any:
        """Create and return a boto3.Session based on current configuration."""
        if not BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is not installed in the environment.")

        with self._lock:
            mode = self._credential_mode
            region = self._region
            key_id = self._access_key_id
            secret = self._secret_access_key

        if mode == "keys":
            if not key_id or not secret:
                raise ValueError("Access Key ID and Secret Access Key must be provided for 'keys' mode.")
            return boto3.Session(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret,
                region_name=region,
            )
        else:
            # Environment / standard AWS credential provider chain
            return boto3.Session(region_name=region)

    def test_connection(self) -> Dict[str, Any]:
        """
        Comprehensive backend connection test verifying:
          1. STS caller identity (authentication & account ID)
          2. EC2 read permissions (ec2:DescribeInstances against selected region)
          3. CloudWatch read permissions (cloudwatch:ListMetrics)
        Returns sanitized, structured report without secrets or tracebacks.
        """
        if not BOTO3_AVAILABLE:
            return {
                "connection_status": "Connection Error",
                "account_id": None,
                "region": self._region,
                "credential_method": self._credential_mode,
                "ec2_access": False,
                "cloudwatch_access": False,
                "errors": ["boto3 is not installed on Master server."],
            }

        result = {
            "connection_status": "Connecting",
            "account_id": None,
            "region": self._region,
            "credential_method": self._credential_mode,
            "ec2_access": False,
            "cloudwatch_access": False,
            "errors": [],
        }

        try:
            session = self.create_session()
        except Exception as exc:
            err_msg = str(exc)
            result["connection_status"] = "Authentication Failed"
            result["errors"].append(f"Configuration error: {err_msg}")
            self._update_status(result["connection_status"], None, result["errors"])
            return result

        # 1. Test Authentication & Account ID via STS
        try:
            sts_client = session.client("sts")
            caller = sts_client.get_caller_identity()
            account_id = caller.get("Account")
            result["account_id"] = account_id
            with self._lock:
                self._account_id = account_id
        except NoCredentialsError:
            result["connection_status"] = "Authentication Failed"
            result["errors"].append("No AWS credentials found in environment or provider chain.")
            self._update_status(result["connection_status"], None, result["errors"])
            return result
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "AuthError")
            msg = ce.response.get("Error", {}).get("Message", "Authentication failed.")
            result["connection_status"] = "Authentication Failed"
            result["errors"].append(f"STS Authentication failed ({code}): {msg}")
            self._update_status(result["connection_status"], None, result["errors"])
            return result
        except EndpointConnectionError:
            result["connection_status"] = "Connection Error"
            result["errors"].append("Unable to connect to AWS STS endpoint. Check Internet connectivity.")
            self._update_status(result["connection_status"], None, result["errors"])
            return result
        except Exception as exc:
            result["connection_status"] = "Connection Error"
            result["errors"].append(f"STS connection error: {str(exc)}")
            self._update_status(result["connection_status"], None, result["errors"])
            return result

        # 2. Test EC2 read access via describe_instances (MaxResults=5) in selected region
        try:
            ec2_client = session.client("ec2", region_name=self._region)
            ec2_client.describe_instances(MaxResults=5)
            result["ec2_access"] = True
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "EC2Error")
            msg = ce.response.get("Error", {}).get("Message", "Access denied.")
            if "Unauthorized" in code or "AccessDenied" in code or "Forbidden" in code:
                result["errors"].append(f"EC2 read permission missing: {code} ({msg})")
            else:
                result["errors"].append(f"EC2 API check failed: {code} ({msg})")
        except EndpointConnectionError:
            result["errors"].append(f"Unable to connect to AWS EC2 endpoint in {self._region}.")
        except Exception as exc:
            result["errors"].append(f"EC2 check error: {str(exc)}")

        # 3. Test CloudWatch read access via list_metrics
        try:
            cw_client = session.client("cloudwatch", region_name=self._region)
            cw_client.list_metrics(Namespace="AWS/EC2", RecentlyActive="PT3H")
            result["cloudwatch_access"] = True
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "CWError")
            msg = ce.response.get("Error", {}).get("Message", "Access denied.")
            if "Unauthorized" in code or "AccessDenied" in code or "Forbidden" in code:
                result["errors"].append(f"CloudWatch read permission missing: {code} ({msg})")
            else:
                result["errors"].append(f"CloudWatch API check failed: {code} ({msg})")
        except EndpointConnectionError:
            result["errors"].append(f"Unable to connect to AWS CloudWatch endpoint in {self._region}.")
        except Exception as exc:
            result["errors"].append(f"CloudWatch check error: {str(exc)}")

        # Determine overall status
        if result["ec2_access"] and result["cloudwatch_access"]:
            result["connection_status"] = "Connected"
        elif result["ec2_access"] or result["cloudwatch_access"]:
            result["connection_status"] = "Permission Denied"
        else:
            if any("permission missing" in e for e in result["errors"]):
                result["connection_status"] = "Permission Denied"
            else:
                result["connection_status"] = "Connection Error"

        self._update_status(result["connection_status"], result["account_id"], result["errors"])
        return result

    def _update_status(self, status: str, account_id: Optional[str], errors: List[str]) -> None:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self._connection_status = status
            if account_id:
                self._account_id = account_id
            self._last_tested_at = now_str
            self._last_error = "; ".join(errors) if errors else None

    def get_public_state(self) -> Dict[str, Any]:
        """Return public safe state (no secrets)."""
        with self._lock:
            return {
                "credential_mode": self._credential_mode,
                "region": self._region,
                "account_id": self._account_id,
                "connection_status": self._connection_status,
                "has_key_id": bool(self._access_key_id),
                "has_secret": bool(self._secret_access_key),
                "last_tested_at": self._last_tested_at,
                "last_error": self._last_error,
                "boto3_available": BOTO3_AVAILABLE,
            }


class AWSDiscoveryService:
    """Discovers EC2 instances, metadata, and status checks."""

    def discover_instances(self, session: Any, region: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover EC2 instances with full metadata and pagination."""
        if not BOTO3_AVAILABLE:
            return []

        ec2 = session.client("ec2", region_name=region)
        instances: List[Dict[str, Any]] = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    res_owner = reservation.get("OwnerId") or account_id
                    for inst in reservation.get("Instances", []):
                        instance_id = inst.get("InstanceId")
                        if not instance_id:
                            continue

                        # Extract name from Tags
                        name = None
                        for tag in inst.get("Tags", []):
                            if tag.get("Key") == "Name":
                                name = tag.get("Value")
                                break

                        # Format launch time
                        launch_time_dt = inst.get("LaunchTime")
                        if isinstance(launch_time_dt, datetime):
                            launch_time_str = launch_time_dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            launch_time_str = str(launch_time_dt) if launch_time_dt else None

                        state = inst.get("State", {}).get("Name", "unknown")
                        az = inst.get("Placement", {}).get("AvailabilityZone", "")

                        platform = inst.get("PlatformDetails") or inst.get("Platform") or "Linux/UNIX"

                        instances.append({
                            "instance_id": instance_id,
                            "account_id": res_owner,
                            "region": region,
                            "name": name or instance_id,
                            "instance_type": inst.get("InstanceType", "unknown"),
                            "state": state,
                            "availability_zone": az,
                            "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "platform": platform,
                            "launch_time": launch_time_str,
                            "system_status": "initializing",
                            "instance_status": "initializing",
                        })
        except Exception as exc:
            logger.error("Error describing instances in region %s: %s", region, exc)
            raise

        # Retrieve EC2 status checks
        if instances:
            try:
                inst_ids = [i["instance_id"] for i in instances]
                status_map = self._get_status_checks(ec2, inst_ids)
                for item in instances:
                    iid = item["instance_id"]
                    if iid in status_map:
                        item["system_status"] = status_map[iid]["system_status"]
                        item["instance_status"] = status_map[iid]["instance_status"]
            except Exception as exc:
                logger.warning("Error fetching instance status checks: %s", exc)

        return instances

    def _get_status_checks(self, ec2_client: Any, instance_ids: List[str]) -> Dict[str, Dict[str, str]]:
        """Query ec2:DescribeInstanceStatus with pagination/batching."""
        status_map: Dict[str, Dict[str, str]] = {}
        # Batch by 100 instances per call
        batch_size = 100
        for i in range(0, len(instance_ids), batch_size):
            batch = instance_ids[i:i + batch_size]
            try:
                resp = ec2_client.describe_instance_status(
                    InstanceIds=batch,
                    IncludeAllInstances=True,
                )
                for item in resp.get("InstanceStatuses", []):
                    iid = item.get("InstanceId")
                    sys_status = item.get("SystemStatus", {}).get("Status", "unknown")
                    inst_status = item.get("InstanceStatus", {}).get("Status", "unknown")
                    status_map[iid] = {
                        "system_status": sys_status,
                        "instance_status": inst_status,
                    }
            except Exception as exc:
                logger.warning("Failed status check batch: %s", exc)

        return status_map


class AWSMetricsService:
    """Queries CloudWatch metrics for EC2 instances with batching."""

    def get_instance_metrics(
        self,
        session: Any,
        region: str,
        instance_id: str,
        minutes: int = 60,
    ) -> Dict[str, Any]:
        """
        Query CloudWatch GetMetricData for CPUUtilization, NetworkIn, NetworkOut.
        Strictly returns RAM as N/A per specification.
        """
        if not BOTO3_AVAILABLE:
            return {"cpu": None, "network_in": None, "network_out": None, "ram": None}

        cw = session.client("cloudwatch", region_name=region)
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)

        queries = [
            {
                "Id": "m_cpu",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    },
                    "Period": 300,
                    "Stat": "Average",
                },
                "ReturnData": True,
            },
            {
                "Id": "m_net_in",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "NetworkIn",
                        "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    },
                    "Period": 300,
                    "Stat": "Average",
                },
                "ReturnData": True,
            },
            {
                "Id": "m_net_out",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "NetworkOut",
                        "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    },
                    "Period": 300,
                    "Stat": "Average",
                },
                "ReturnData": True,
            },
        ]

        metric_result: Dict[str, Any] = {
            "cpu": None,
            "network_in": None,
            "network_out": None,
            "ram": None,
            "ram_status": "N/A (Standard CloudWatch metric unavailable)",
            "history": [],
            "last_updated": now.strftime("%Y-%m-%d %H:%M:%S"),
        }

        try:
            resp = cw.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start_time,
                EndTime=now,
                ScanBy="TimestampAscending",
            )
            for r in resp.get("MetricResults", []):
                qid = r.get("Id")
                timestamps = r.get("Timestamps", [])
                values = r.get("Values", [])

                latest_val = values[-1] if values else None

                if qid == "m_cpu":
                    metric_result["cpu"] = round(float(latest_val), 2) if latest_val is not None else None
                elif qid == "m_net_in":
                    metric_result["network_in"] = round(float(latest_val), 2) if latest_val is not None else None
                elif qid == "m_net_out":
                    metric_result["network_out"] = round(float(latest_val), 2) if latest_val is not None else None

                # Build combined history points if needed
                for ts, val in zip(timestamps, values):
                    ts_str = ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    metric_result["history"].append({
                        "metric": qid,
                        "timestamp": ts_str,
                        "value": round(float(val), 2),
                    })
        except Exception as exc:
            logger.warning("Error fetching CloudWatch metrics for %s: %s", instance_id, exc)

        return metric_result


class AWSAnomalyDetector:
    """Evaluates deterministic operational anomalies for AWS EC2 instances."""

    def evaluate_instance(self, instance: Dict[str, Any], metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate structured deterministic findings without hallucination."""
        anomalies: List[Dict[str, Any]] = []
        name = instance.get("name") or instance.get("instance_id")
        state = (instance.get("state") or "").lower()

        # 1. State anomalies
        if state == "stopped":
            anomalies.append({
                "id": f"AWS-STATE-STOPPED-{instance.get('instance_id')}",
                "category": "LIFECYCLE",
                "severity": "WARNING",
                "title": "EC2 Instance Stopped",
                "observed_value": "stopped",
                "baseline": "running",
                "explanation": f"Instance {name} is in stopped state.",
                "recommendation": "Review AWS console or scheduler if the instance was expected to be running.",
            })
        elif state not in ("running", "stopped", "pending"):
            anomalies.append({
                "id": f"AWS-STATE-ABNORMAL-{instance.get('instance_id')}",
                "category": "LIFECYCLE",
                "severity": "WARNING",
                "title": f"EC2 Instance State: {state}",
                "observed_value": state,
                "baseline": "running",
                "explanation": f"Instance {name} is in {state} state.",
                "recommendation": "Monitor state transition until instance is stable.",
            })

        # 2. Status check failures
        sys_status = (instance.get("system_status") or "").lower()
        if sys_status in ("failed", "impaired"):
            anomalies.append({
                "id": f"AWS-HEALTH-SYSFAIL-{instance.get('instance_id')}",
                "category": "HARDWARE",
                "severity": "CRITICAL",
                "title": "AWS System Status Check Failed",
                "observed_value": sys_status,
                "baseline": "passed",
                "explanation": f"AWS underlying infrastructure issue detected on instance {name}.",
                "recommendation": "Stop and start the instance to migrate to healthy AWS host hardware.",
            })

        inst_status = (instance.get("instance_status") or "").lower()
        if inst_status in ("failed", "impaired"):
            anomalies.append({
                "id": f"AWS-HEALTH-INSTFAIL-{instance.get('instance_id')}",
                "category": "OS",
                "severity": "CRITICAL",
                "title": "EC2 Instance Status Check Failed",
                "observed_value": inst_status,
                "baseline": "passed",
                "explanation": f"Operating system or software failure inside instance {name}.",
                "recommendation": "Inspect system logs, kernel issues, file system corruption, or network misconfiguration.",
            })

        # 3. CPU utilization anomalies
        cpu = metrics.get("cpu")
        if cpu is not None:
            if cpu >= 90.0:
                anomalies.append({
                    "id": f"AWS-CPU-CRITICAL-{instance.get('instance_id')}",
                    "category": "CPU",
                    "severity": "CRITICAL",
                    "title": "EC2 CPU Critical (>90%)",
                    "observed_value": f"{cpu}%",
                    "baseline": "< 75%",
                    "explanation": f"Instance {name} CPU is at critical utilization ({cpu}%).",
                    "recommendation": "Investigate running processes or scale up instance type.",
                })
            elif cpu >= 75.0:
                anomalies.append({
                    "id": f"AWS-CPU-ELEVATED-{instance.get('instance_id')}",
                    "category": "CPU",
                    "severity": "WARNING",
                    "title": "EC2 CPU Elevated (>75%)",
                    "observed_value": f"{cpu}%",
                    "baseline": "< 75%",
                    "explanation": f"Instance {name} CPU utilization is elevated ({cpu}%).",
                    "recommendation": "Monitor workload and verify if elevated usage is expected.",
                })

        return anomalies


class AWSService:
    """Master facade for AWS Cloud / EC2 Read-Only Monitoring."""

    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(AWSService, cls).__new__(cls)
                cls._instance._init_service()
            return cls._instance

    def _init_service(self) -> None:
        self.connection = AWSConnectionService()
        self.discovery = AWSDiscoveryService()
        self.metrics = AWSMetricsService()
        self.anomalies = AWSAnomalyDetector()
        self._load_persisted_config()

    def _load_persisted_config(self) -> None:
        """Load safe non-secret configuration from SQLite if available."""
        try:
            conn = get_connection()
            try:
                row = conn.execute(
                    "SELECT credential_mode, region, account_id, connection_status, last_tested_at, last_error "
                    "FROM aws_config ORDER BY id DESC LIMIT 1;"
                ).fetchone()
                if row:
                    self.connection.configure(
                        credential_mode=row["credential_mode"],
                        region=row["region"],
                    )
                    with self.connection._lock:
                        self.connection._account_id = row["account_id"]
                        self.connection._connection_status = row["connection_status"]
                        self.connection._last_tested_at = row["last_tested_at"]
                        self.connection._last_error = row["last_error"]
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Could not load persisted AWS config: %s", exc)

    def _persist_config(self) -> None:
        """Persist safe non-secret config state to database."""
        state = self.connection.get_public_state()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = get_connection()
            try:
                conn.execute(
                    """INSERT INTO aws_config
                       (credential_mode, region, account_id, connection_status, last_tested_at, last_error, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        state["credential_mode"],
                        state["region"],
                        state["account_id"],
                        state["connection_status"],
                        state["last_tested_at"],
                        state["last_error"],
                        now_str,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Could not persist AWS config: %s", exc)

    def get_status(self) -> Dict[str, Any]:
        """Return current AWS monitoring status."""
        state = self.connection.get_public_state()
        instances_count = len(self.list_instances())
        state["instances_count"] = instances_count
        return state

    def update_config(
        self,
        credential_mode: str,
        region: str,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Configure AWS monitoring settings."""
        self.connection.configure(
            credential_mode=credential_mode,
            region=region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
        )
        self._persist_config()
        return self.get_status()

    def test_connection(self) -> Dict[str, Any]:
        """Run connection test and persist result."""
        result = self.connection.test_connection()
        self._persist_config()
        return result

    def discover_instances(self) -> List[Dict[str, Any]]:
        """Run EC2 discovery in selected region and persist to database."""
        session = self.connection.create_session()
        state = self.connection.get_public_state()
        region = state["region"]
        account_id = state.get("account_id")

        instances = self.discovery.discover_instances(session, region, account_id)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = get_connection()
            try:
                for inst in instances:
                    conn.execute(
                        """INSERT INTO aws_instances
                           (instance_id, account_id, region, name, instance_type, state,
                            availability_zone, private_ip, public_ip, platform, launch_time,
                            system_status, instance_status, last_checked, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(instance_id) DO UPDATE SET
                             account_id=excluded.account_id,
                             region=excluded.region,
                             name=excluded.name,
                             instance_type=excluded.instance_type,
                             state=excluded.state,
                             availability_zone=excluded.availability_zone,
                             private_ip=excluded.private_ip,
                             public_ip=excluded.public_ip,
                             platform=excluded.platform,
                             launch_time=excluded.launch_time,
                             system_status=excluded.system_status,
                             instance_status=excluded.instance_status,
                             last_checked=excluded.last_checked,
                             updated_at=excluded.updated_at;""",
                        (
                            inst["instance_id"],
                            inst["account_id"],
                            inst["region"],
                            inst["name"],
                            inst["instance_type"],
                            inst["state"],
                            inst["availability_zone"],
                            inst["private_ip"],
                            inst["public_ip"],
                            inst["platform"],
                            inst["launch_time"],
                            inst["system_status"],
                            inst["instance_status"],
                            now_str,
                            now_str,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            logger.error("Failed to persist discovered instances: %s", exc)

        return self.list_instances()

    def list_instances(self) -> List[Dict[str, Any]]:
        """List all discovered AWS instances with latest metrics summary."""
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM aws_instances ORDER BY name ASC, instance_id ASC;"
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                # Fetch latest CPU from aws_metrics if available
                m_row = conn.execute(
                    "SELECT value FROM aws_metrics WHERE instance_id = ? AND metric_name = 'CPUUtilization' "
                    "ORDER BY timestamp DESC LIMIT 1;",
                    (item["instance_id"],),
                ).fetchone()
                item["latest_cpu"] = m_row["value"] if m_row else None
                result.append(item)
            return result
        finally:
            conn.close()

    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Fetch single instance details and live metrics."""
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM aws_instances WHERE instance_id = ?;",
                (instance_id,),
            ).fetchone()
            if not row:
                return None
            instance = dict(row)
        finally:
            conn.close()

        # Fetch CloudWatch metrics
        metrics = {"cpu": None, "network_in": None, "network_out": None, "ram": None, "ram_status": "N/A"}
        try:
            session = self.connection.create_session()
            metrics = self.metrics.get_instance_metrics(
                session, instance["region"], instance_id, minutes=60
            )
            # Record latest CPU snapshot if present
            if metrics.get("cpu") is not None:
                self._record_metric_snapshot(instance_id, instance["region"], "CPUUtilization", metrics["cpu"], "Percent")
            if metrics.get("network_in") is not None:
                self._record_metric_snapshot(instance_id, instance["region"], "NetworkIn", metrics["network_in"], "Bytes")
            if metrics.get("network_out") is not None:
                self._record_metric_snapshot(instance_id, instance["region"], "NetworkOut", metrics["network_out"], "Bytes")
        except Exception as exc:
            logger.warning("Could not fetch live metrics for instance %s: %s", instance_id, exc)

        # Evaluate deterministic anomalies
        anomalies = self.anomalies.evaluate_instance(instance, metrics)

        return {
            "instance": instance,
            "metrics": metrics,
            "anomalies": anomalies,
        }

    def _record_metric_snapshot(self, instance_id: str, region: str, metric_name: str, value: float, unit: str) -> None:
        try:
            conn = get_connection()
            try:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT INTO aws_metrics (instance_id, region, metric_name, timestamp, value, unit, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'CloudWatch');",
                    (instance_id, region, metric_name, now_str, value, unit),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Could not record metric snapshot: %s", exc)


# Global singleton service
aws_service = AWSService()
