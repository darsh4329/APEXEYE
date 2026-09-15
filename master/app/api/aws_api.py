"""
APEXEYE MASTER — AWS Monitoring REST API

Endpoints:
  GET  /api/aws/status               — AWS connection and monitoring status
  POST /api/aws/config               — Configure AWS credential mode, region, keys
  POST /api/aws/test-connection      — Execute live connectivity & permissions test
  POST /api/aws/discover             — Discover EC2 instances in configured region
  GET  /api/aws/instances            — List all discovered EC2 instances
  GET  /api/aws/instances/<id>       — Get EC2 instance details, health, and metrics
  GET  /api/aws/instances/<id>/metrics — Get CloudWatch metrics for an instance

Security:
  - Restricted strictly to Master localhost/loopback (@require_admin).
  - Validates all inputs; rejects malformed bodies and invalid parameters.
  - Never logs or exposes AWS secret keys in responses.
  - Sanitizes all AWS exceptions without raw tracebacks.
"""

import re
from flask import Blueprint, jsonify, request

from master.app.api.security import require_admin
from master.app.services.aws_service import aws_service, AWS_STANDARD_REGIONS
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.api.aws")

aws_bp = Blueprint("aws_api", __name__)

_REGION_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
_INSTANCE_ID_REGEX = re.compile(r"^i-[0-9a-f]{8,17}$")


@aws_bp.route("/aws/status", methods=["GET"])
@require_admin
def get_status():
    """Return current AWS connection, configuration, and instance count."""
    try:
        status = aws_service.get_status()
        status["available_regions"] = AWS_STANDARD_REGIONS
        return jsonify(status), 200
    except Exception as exc:
        logger.error("Error retrieving AWS status: %s", exc)
        return jsonify({"error": "Failed to retrieve AWS monitoring status"}), 500


@aws_bp.route("/aws/config", methods=["POST"])
@require_admin
def update_config():
    """Update AWS credential mode, region, and optional credentials."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    credential_mode = data.get("credential_mode", "env")
    if credential_mode not in ("env", "keys"):
        return jsonify({"error": "credential_mode must be either 'env' or 'keys'"}), 400

    region = (data.get("region") or "").strip()
    if not region:
        region = "us-east-1"
    elif not _REGION_REGEX.match(region):
        return jsonify({"error": f"Invalid AWS region format: '{region}'"}), 400

    access_key_id = data.get("access_key_id")
    secret_access_key = data.get("secret_access_key")

    if credential_mode == "keys":
        if access_key_id is not None:
            access_key_id = str(access_key_id).strip()
            if access_key_id and not re.match(r"^[A-Z0-9]{16,128}$", access_key_id):
                return jsonify({"error": "Invalid AWS Access Key ID format"}), 400
        if secret_access_key is not None:
            secret_access_key = str(secret_access_key).strip()

    try:
        updated = aws_service.update_config(
            credential_mode=credential_mode,
            region=region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
        )
        updated["available_regions"] = AWS_STANDARD_REGIONS
        return jsonify(updated), 200
    except Exception as exc:
        logger.error("Error saving AWS config: %s", exc)
        return jsonify({"error": "Failed to update AWS configuration"}), 500


@aws_bp.route("/aws/test-connection", methods=["POST"])
@require_admin
def test_connection():
    """Test AWS connectivity, STS authentication, EC2 read access, and CloudWatch access."""
    try:
        result = aws_service.test_connection()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Error executing AWS connection test: %s", exc)
        return jsonify({
            "connection_status": "Connection Error",
            "account_id": None,
            "region": aws_service.get_status().get("region", "us-east-1"),
            "credential_method": aws_service.get_status().get("credential_mode", "env"),
            "ec2_access": False,
            "cloudwatch_access": False,
            "errors": ["An unexpected error occurred during connection test."],
        }), 500


@aws_bp.route("/aws/discover", methods=["POST"])
@require_admin
def discover_instances():
    """Trigger EC2 instance discovery in the configured region."""
    try:
        instances = aws_service.discover_instances()
        return jsonify({
            "message": f"Successfully discovered {len(instances)} EC2 instances.",
            "count": len(instances),
            "instances": instances,
        }), 200
    except Exception as exc:
        err_msg = str(exc)
        logger.error("Error discovering EC2 instances: %s", exc)
        # Sanitize message so no secrets or internal paths leak
        if "Unauthorized" in err_msg or "AccessDenied" in err_msg:
            return jsonify({"error": "AWS permission denied: Ensure ec2:DescribeInstances is granted."}), 403
        elif "NoCredentialsError" in err_msg or "credential" in err_msg.lower():
            return jsonify({"error": "AWS credentials missing or invalid. Please check configuration."}), 401
        return jsonify({"error": "Failed to discover EC2 instances. Check AWS credentials and region connectivity."}), 500


@aws_bp.route("/aws/instances", methods=["GET"])
@require_admin
def list_instances():
    """List all previously discovered EC2 instances."""
    try:
        instances = aws_service.list_instances()
        return jsonify(instances), 200
    except Exception as exc:
        logger.error("Error listing AWS instances: %s", exc)
        return jsonify({"error": "Failed to list AWS instances"}), 500


@aws_bp.route("/aws/instances/<instance_id>", methods=["GET"])
@require_admin
def get_instance_detail(instance_id: str):
    """Get full details, health checks, CloudWatch metrics, and anomalies for an EC2 instance."""
    clean_id = instance_id.strip()
    if not _INSTANCE_ID_REGEX.match(clean_id):
        return jsonify({"error": f"Invalid EC2 instance ID format: '{clean_id}'"}), 400

    try:
        detail = aws_service.get_instance(clean_id)
        if not detail:
            return jsonify({"error": f"EC2 instance '{clean_id}' not found."}), 404
        return jsonify(detail), 200
    except Exception as exc:
        logger.error("Error fetching detail for instance %s: %s", clean_id, exc)
        return jsonify({"error": "Failed to retrieve EC2 instance details"}), 500


@aws_bp.route("/aws/instances/<instance_id>/metrics", methods=["GET"])
@require_admin
def get_instance_metrics(instance_id: str):
    """Retrieve CloudWatch metrics for an instance."""
    clean_id = instance_id.strip()
    if not _INSTANCE_ID_REGEX.match(clean_id):
        return jsonify({"error": f"Invalid EC2 instance ID format: '{clean_id}'"}), 400

    try:
        detail = aws_service.get_instance(clean_id)
        if not detail:
            return jsonify({"error": f"EC2 instance '{clean_id}' not found."}), 404
        return jsonify(detail.get("metrics", {})), 200
    except Exception as exc:
        logger.error("Error fetching metrics for instance %s: %s", clean_id, exc)
        return jsonify({"error": "Failed to retrieve instance metrics"}), 500
