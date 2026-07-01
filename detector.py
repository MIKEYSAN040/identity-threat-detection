import json
import math
from datetime import datetime
from collections import defaultdict
MITRE_MAP = {
    "impossible_travel":    {"id": "T1078",     "name": "Valid Accounts",      "tactic": "Initial Access"},
    "off_hours_access":     {"id": "T1078.004", "name": "Cloud Accounts",      "tactic": "Defense Evasion"},
    "brute_force":          {"id": "T1110",     "name": "Brute Force",         "tactic": "Credential Access"},
    "dormant_account":      {"id": "T1078.003", "name": "Local Accounts",      "tactic": "Persistence"},
    "privilege_escalation": {"id": "T1098",     "name": "Account Manipulation","tactic": "Privilege Escalation"},
}
PRIV_ESC_EVENTS = {
    "IAM:AttachUserPolicy", "IAM:CreateUser", "IAM:UpdateLoginProfile",
    "IAM:PutUserPolicy", "IAM:AddUserToGroup", "CloudTrail:DeleteTrail",
    "IAM:CreateAccessKey"
}

RISK_WEIGHTS = {
    "impossible_travel": 90,
    "brute_force": 85,
    "privilege_escalation": 95,
    "off_hours_access": 60,
    "dormant_account": 70,
}
def haversine(lat1, lon1, lat2, lon2):
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
def parse_time(ts):
    return datetime.fromisoformat(ts)

def load_logs(path="data/simulated_logs.json"):
    with open(path) as f:
        return json.load(f)
    
# IMPOSSIBLE TRAVEL REAL DETECTION 
def detect_impossible_travel(user_events):
    findings = []
    logins = [e for e in user_events if e["eventName"] == "ConsoleLogin" and e["status"] == "Success"]
    logins.sort(key=lambda x: x["eventTime"])

    for i in range(len(logins) - 1):
        e1, e2 = logins[i], logins[i+1]
        t1, t2 = parse_time(e1["eventTime"]), parse_time(e2["eventTime"])
        mins = (t2 - t1).total_seconds() / 60

        if mins < 60:
            loc1, loc2 = e1["location"], e2["location"]
            dist = haversine(loc1["lat"], loc1["lon"], loc2["lat"], loc2["lon"])

            if dist > 500:
                findings.append({
                    "type": "impossible_travel",
                    "detail": f"Login from {loc1['city']} then {loc2['city']} within {int(mins)} mins ({int(dist)} km apart)",
                    "eventTime": e2["eventTime"],
                    "ip": e2["sourceIPAddress"],
                    "mitre": MITRE_MAP["impossible_travel"],
                    "risk_score": RISK_WEIGHTS["impossible_travel"]
                })

    return findings
def detect_off_hours(user_events):
    findings = []
    logins = [e for e in user_events if e["eventName"] == "ConsoleLogin" and e["status"] == "Success"]

    for e in logins:
        hour = parse_time(e["eventTime"]).hour
        if hour < 4 or hour >= 23:
            findings.append({
                "type": "off_hours_access",
                "detail": f"Login at {hour:02d}:00 (outside business hours)",
                "eventTime": e["eventTime"],
                "ip": e["sourceIPAddress"],
                "mitre": MITRE_MAP["off_hours_access"],
                "risk_score": RISK_WEIGHTS["off_hours_access"]
            })

    return findings
#BRUTEFORCE
def detect_brute_force(user_events):
    findings = []
    failures = [e for e in user_events if e["eventName"] == "ConsoleLogin" and e["status"] == "Failure"]
    successes = [e for e in user_events if e["eventName"] == "ConsoleLogin" and e["status"] == "Success"]

    if len(failures) >= 5:
        for s in successes:
            st = parse_time(s["eventTime"])
            nearby_fails = [f for f in failures if abs((parse_time(f["eventTime"]) - st).total_seconds()) < 600]

            if len(nearby_fails) >= 5:
                findings.append({
                    "type": "brute_force",
                    "detail": f"{len(nearby_fails)} failed logins followed by success within 10 mins",
                    "eventTime": s["eventTime"],
                    "ip": s["sourceIPAddress"],
                    "mitre": MITRE_MAP["brute_force"],
                    "risk_score": RISK_WEIGHTS["brute_force"]
                })

    return findings
#DORMANT ACCOUNT
def detect_dormant_account(user_events, dormant_days=25):
    findings = []
    logins = [e for e in user_events if e["eventName"] == "ConsoleLogin" and e["status"] == "Success"]

    if not logins:
        return findings

    logins.sort(key=lambda x: x["eventTime"])
    times = [parse_time(e["eventTime"]) for e in logins]

    for i in range(1, len(times)):
        gap = (times[i] - times[i-1]).days
        if gap >= dormant_days:
            findings.append({
                "type": "dormant_account",
                "detail": f"Account inactive for {gap} days then suddenly active",
                "eventTime": logins[i]["eventTime"],
                "ip": logins[i]["sourceIPAddress"],
                "mitre": MITRE_MAP["dormant_account"],
                "risk_score": RISK_WEIGHTS["dormant_account"]
            })

    return findings
#PRIVELAGE ESCALATIONS
def detect_privilege_escalation(user_events):
    findings = []
    priv_events = [e for e in user_events if e["eventName"] in PRIV_ESC_EVENTS]

    if len(priv_events) >= 3:
        findings.append({
            "type": "privilege_escalation",
            "detail": f"Sensitive IAM actions: {', '.join(set(e['eventName'] for e in priv_events))}",
            "eventTime": priv_events[-1]["eventTime"],
            "ip": priv_events[-1]["sourceIPAddress"],
            "mitre": MITRE_MAP["privilege_escalation"],
            "risk_score": RISK_WEIGHTS["privilege_escalation"]
        })

    return findings
def classify_risk(score):
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    return "LOW"
def run_detections(logs):
    by_user = defaultdict(list)
    for event in logs:
        by_user[event["username"]].append(event)

    results = []
    for user, events in by_user.items():
        findings = []
        findings += detect_impossible_travel(events)
        findings += detect_off_hours(events)
        findings += detect_brute_force(events)
        findings += detect_dormant_account(events)
        findings += detect_privilege_escalation(events)

        if findings:
            max_score = max(f["risk_score"] for f in findings)
            results.append({
                "username": user,
                "total_events": len(events),
                "findings": findings,
                "risk_score": max_score,
                "risk_level": classify_risk(max_score),
                "finding_count": len(findings)
            })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results
def get_summary(results):
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total_alerts": 0}
    for r in results:
        summary[r["risk_level"]] += 1
        summary["total_alerts"] += r["finding_count"]
    return summary