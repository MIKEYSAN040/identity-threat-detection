# Identity Threat Detection System

A behavioral analytics tool that detects compromised or abused AWS identities 
by analyzing user activity logs. Built to simulate real SOC analyst workflow — 
correlating weak signals into actionable threat findings.

---

## Problem It Solves

Traditional IAM audits tell you **who has access**.  
This tool tells you **how that access is being used** — and whether that 
behavior looks like an attacker.

---

## Detections

| Detection | Description | MITRE ATT&CK |
|---|---|---|
| Impossible Travel | Login from two distant locations within minutes | T1078 |
| Off-Hours Access | Console login between 11PM and 4AM | T1078.004 |
| Brute Force | 5+ failed logins followed by success within 10 mins | T1110 |
| Dormant Account | Account inactive 25+ days then suddenly active | T1078.003 |
| Privilege Escalation | Sensitive IAM actions chained together | T1098 |

---

## Tech Stack

- **Python** — detection engine, log parsing
- **Flask** — web dashboard and REST API
- **Boto3** — AWS CloudTrail integration
- **Pandas** — log analysis
- **OpenPyXL** — Excel report generation
- **Chart.js** — dashboard visualizations
- **AWS EC2** — deployment ready

---

## Project Structure

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/MIKEYSAN040/identity-threat-detection
cd identity-threat-detection

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate simulated logs
python data/generate_logs.py

# 4. Run
python app.py

# 5. Open browser
http://localhost:5000
```

---

## AWS CloudTrail Integration

To analyze real AWS logs:

1. Configure AWS credentials:
```bash
aws configure
```

2. Click **Fetch CloudTrail** on the dashboard and enter your region.

3. Switch dropdown to **AWS CloudTrail** and re-run analysis.

> Requires `cloudtrail:LookupEvents` IAM permission.

---

## Dashboard Features

- Risk KPI cards (Critical / High / Medium / Low)
- Risk distribution donut chart
- Detection type bar chart
- Color coded findings table with MITRE ATT&CK mapping
- One click Excel report download

---

## Skills Demonstrated

- Behavioral threat detection logic
- MITRE ATT&CK framework mapping
- AWS CloudTrail integration via Boto3
- SOC L1 triage workflow
- Python Flask REST API development
- Excel report generation with OpenPyXL
- AWS EC2 deployment ready

---
