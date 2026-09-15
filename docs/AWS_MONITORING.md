# APEXEYE — AWS Cloud / EC2 Read-Only Monitoring Guide

This guide describes how to configure and monitor Amazon Web Services (AWS) EC2 instances within the APEXEYE Master management system.

---

## 1. Overview & Architecture

APEXEYE provides **agentless, read-only monitoring** of AWS EC2 instances and CloudWatch metrics.

```
       APEXEYE Master
             │
             │ HTTPS (TLS via boto3 official AWS SDK)
             ▼
         AWS APIs
       ┌─────┴──────┐
       ▼            ▼
   Amazon EC2   CloudWatch
```

### Key Operational Characteristics
- **Agentless**: APEXEYE does **NOT** require installing an agent on the remote EC2 instances.
- **Internet Communication**: AWS instances do **NOT** need to be on the same local Wi-Fi or LAN as the APEXEYE Master. The Master communicates with AWS over the public Internet via HTTPS.
- **Strictly Read-Only**: APEXEYE never requests or performs destructive operations. It cannot start, stop, reboot, terminate, or modify EC2 instances or CloudWatch alarms.
- **No Root Credentials**: Never use AWS account root credentials. Use a dedicated, least-privilege IAM user or role.
- **RAM Policy**: Standard EC2 CloudWatch metrics do not provide OS-level RAM utilization out of the box. RAM is strictly reported as **`N/A`** and is never fabricated.

---

## 2. Least-Privilege IAM Policy Setup

To follow security best practices, create an IAM Policy with **only the 5 read-only permissions** required by APEXEYE:

1. `sts:GetCallerIdentity` (Verify credentials and resolve AWS Account ID)
2. `ec2:DescribeInstances` (Discover EC2 instances, metadata, and IP addresses)
3. `ec2:DescribeInstanceStatus` (Fetch system and instance status checks)
4. `cloudwatch:GetMetricData` (Retrieve CPUUtilization, NetworkIn, NetworkOut metrics)
5. `cloudwatch:ListMetrics` (Verify CloudWatch read access during connection testing)

### IAM Policy JSON Document
Attach the following JSON policy to your dedicated APEXEYE IAM User or Role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ApexEyeReadOnlySTS",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ApexEyeReadOnlyEC2",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ApexEyeReadOnlyCloudWatch",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetMetricData",
                "cloudwatch:ListMetrics"
            ],
            "Resource": "*"
        }
    ]
}
```

> [!WARNING]
> Do NOT grant `ec2:StartInstances`, `ec2:StopInstances`, `ec2:RebootInstances`, `ec2:TerminateInstances`, or any `iam:*` permissions. APEXEYE is strictly a monitoring subsystem.

---

## 3. Credential Options

APEXEYE supports two flexible credential modes. You can select either mode in the Master Dashboard under the **AWS Cloud** tab:

### Option A — Environment / AWS Credential Provider Chain
Ideal for production deployments, EC2 instances with IAM instance profiles, or developer workstations with existing AWS CLI setups:
- APEXEYE reads credentials automatically using the standard boto3 credential resolution order:
  1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION`).
  2. Shared credentials file (`~/.aws/credentials` and `~/.aws/config`).
  3. IAM role attached to the Master host or container metadata service.
- **No credentials need to be pasted into the APEXEYE UI.**

### Option B — APEXEYE Credential Entry
Allows entering credentials directly into the APEXEYE Dashboard:
- Enter your **AWS Access Key ID**, **AWS Secret Access Key**, and select the **AWS Target Region**.
- **Security Guarantee**:
  - The Secret Access Key is held in **runtime session memory only**.
  - It is **never** written to database tables or configuration files.
  - It is **never** logged to application logs or audit logs.
  - It is **never** returned in API responses or visible in browser developer tools.
  - It is masked in the UI with a toggle visibility button.

---

## 4. Step-by-Step Configuration in APEXEYE

1. Open the APEXEYE Master Dashboard in your browser (`http://127.0.0.1:9100`).
2. Click the **☁️ AWS Cloud** tab in the top navigation bar.
3. Under **AWS Credentials & Region Setup**:
   - Choose **Option A** (Environment) or **Option B** (Access Key + Secret Key).
   - If Option B is chosen, enter your `AWS Access Key ID` and `AWS Secret Access Key`.
   - Select your AWS region (e.g. `ap-south-1`, `us-east-1`, `us-west-2`, `eu-west-1`).
4. Click **💾 Save Settings**.
5. Click **⚡ Test Connection**:
   - APEXEYE tests STS authentication, EC2 read permissions against the selected region, and CloudWatch metrics access.
   - The status badge will transition to `🟢 Connected` upon successful verification.
6. Click **🔍 Discover Instances**:
   - APEXEYE queries EC2 and CloudWatch to discover all instances in the selected region.
   - Metadata (Name tag, instance type, state, AZ, IPs, launch time, status checks, live CPU %, network metrics) will populate in the interactive fleet table.

---

## 5. Inspecting EC2 Instances

- Click on any instance row in the table or click **🔍 Inspect** to open the **EC2 Instance Monitor**:
  - **Identity Matrix**: Name, Instance ID, Account ID, Region, AZ, Type, Platform, Private & Public IPs, Launch Time.
  - **Health Status**: Lifecycle State (Running/Stopped), System Status Check, and Instance Status Check.
  - **CloudWatch Metrics**: Live CPU Utilization %, Network In bytes, Network Out bytes, and RAM (reported as `N/A`).
  - **Operational Findings**: Automated deterministic findings (e.g., CPU Critical >90%, CPU Elevated >75%, System Check Failure, Instance Stopped).

---

## 6. Frequently Asked Questions (FAQ)

**Q: Why does RAM show N/A?**  
A: Amazon EC2 basic and detailed CloudWatch monitoring measures hypervisor-level metrics (CPU, disk I/O, network I/O). Operating system memory allocation is an internal OS metric. APEXEYE strictly reports `N/A` for RAM and never fabricates fake telemetry.

**Q: Can APEXEYE stop or reboot my instances?**  
A: No. The APEXEYE Command Center and AWS subsystem are strictly monitoring-only. No control commands exist in the codebase.

**Q: What happens if AWS is unreachable or credentials expire?**  
A: APEXEYE will gracefully update the AWS connection status to `Connection Error` or `Authentication Failed`. It will **never** freeze, crash, or impact local computer and CCTV monitoring.
