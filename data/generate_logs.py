import json
import random
from datetime import datetime, timedelta

users = ["prajwal", "akshay", "preeti", "muskan", "harish", "manoj", "vinayak", "darshan"]

locations = [
    {"city": "Mumbai",   "country": "IN", "lat": 19.07,  "lon": 72.87},
    {"city": "New York", "country": "US", "lat": 40.71,  "lon": -74.00},
    {"city": "London",   "country": "GB", "lat": 51.50,  "lon": -0.12},
    {"city": "Tokyo",    "country": "JP", "lat": 35.68,  "lon": 139.69},
    {"city": "Sydney",   "country": "AU", "lat": -33.86, "lon": 151.20},
]

resources = [
    "S3:GetObject",
    "EC2:StartInstances",
    "EC2:DescribeInstances",
    "RDS:DescribeDBInstances",
    "Lambda:InvokeFunction",
    "S3:ListBuckets",
    "EC2:StopInstances",
    "S3:PutObject"
]

def random_time(base_date, hour_min=8, hour_max=18):
    hour = random.randint(hour_min, hour_max)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=second)

def generate_logs():
    logs = []
    base = datetime.now() - timedelta(days=30)

    for user in users:
        home_loc = random.choice(locations[:2])
        for day in range(28):
            if random.random() > 0.3:
                event_time = random_time(base + timedelta(days=day))
                logs.append({
                    "eventTime": event_time.isoformat(),
                    "username": user,
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                    "location": home_loc,
                    "status": "Success",
                    "userAgent": "Mozilla/5.0"
                })
                for _ in range(random.randint(1, 4)):
                    logs.append({
                        "eventTime": (event_time + timedelta(minutes=random.randint(1, 60))).isoformat(),
                        "username": user,
                        "eventName": random.choice(resources),
                        "sourceIPAddress": f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                        "location": home_loc,
                        "status": "Success",
                        "userAgent": "aws-cli/2.0"
                    })

    # --- INJECT ANOMALIES ---

    # 1. Impossible Travel
    t1 = (base + timedelta(days=29)).replace(hour=10, minute=0)
    logs.append({"eventTime": t1.isoformat(), "username": "darshan", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "103.10.10.1", "location": locations[0], "status": "Success", "userAgent": "Mozilla/5.0"})
    logs.append({"eventTime": (t1 + timedelta(minutes=5)).isoformat(), "username": "darshan", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "54.20.30.1", "location": locations[1], "status": "Success", "userAgent": "Mozilla/5.0"})

    # 2. Off-Hours Access
    t2 = (base + timedelta(days=28)).replace(hour=2, minute=15)
    logs.append({"eventTime": t2.isoformat(), "username": "prajwal", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "192.168.1.50", "location": locations[0], "status": "Success", "userAgent": "Mozilla/5.0"})
    logs.append({"eventTime": (t2 + timedelta(minutes=10)).isoformat(), "username": "prajwal", "eventName": "IAM:CreateUser",
                 "sourceIPAddress": "192.168.1.50", "location": locations[0], "status": "Success", "userAgent": "aws-cli/2.0"})

    # 3. Brute Force
    t3 = (base + timedelta(days=27)).replace(hour=14, minute=0)
    for i in range(6):
        logs.append({"eventTime": (t3 + timedelta(minutes=i)).isoformat(), "username": "akshay", "eventName": "ConsoleLogin",
                     "sourceIPAddress": "185.220.101.5", "location": locations[2], "status": "Failure", "userAgent": "python-requests/2.28"})
    logs.append({"eventTime": (t3 + timedelta(minutes=7)).isoformat(), "username": "akshay", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "185.220.101.5", "location": locations[2], "status": "Success", "userAgent": "python-requests/2.28"})

    # 4. Dormant Account
    t4 = (base + timedelta(days=29)).replace(hour=11, minute=30)
    logs.append({"eventTime": t4.isoformat(), "username": "manoj", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "77.88.55.80", "location": locations[3], "status": "Success", "userAgent": "Mozilla/5.0"})
    logs.append({"eventTime": (t4 + timedelta(minutes=5)).isoformat(), "username": "manoj", "eventName": "S3:GetObject",
                 "sourceIPAddress": "77.88.55.80", "location": locations[3], "status": "Success", "userAgent": "aws-cli/2.0"})

    # 5. Privilege Escalation
    t5 = (base + timedelta(days=29)).replace(hour=16, minute=0)
    logs.append({"eventTime": t5.isoformat(), "username": "preeti", "eventName": "ConsoleLogin",
                 "sourceIPAddress": "103.5.6.7", "location": locations[0], "status": "Success", "userAgent": "Mozilla/5.0"})
    logs.append({"eventTime": (t5 + timedelta(minutes=2)).isoformat(), "username": "preeti", "eventName": "IAM:AttachUserPolicy",
                 "sourceIPAddress": "103.5.6.7", "location": locations[0], "status": "Success", "userAgent": "aws-cli/2.0"})
    logs.append({"eventTime": (t5 + timedelta(minutes=3)).isoformat(), "username": "preeti", "eventName": "IAM:CreateUser",
                 "sourceIPAddress": "103.5.6.7", "location": locations[0], "status": "Success", "userAgent": "aws-cli/2.0"})
    logs.append({"eventTime": (t5 + timedelta(minutes=4)).isoformat(), "username": "preeti", "eventName": "CloudTrail:DeleteTrail",
                 "sourceIPAddress": "103.5.6.7", "location": locations[0], "status": "Success", "userAgent": "aws-cli/2.0"})

    logs.sort(key=lambda x: x["eventTime"])

    with open("data/simulated_logs.json", "w") as f:
        json.dump(logs, f, indent=2)

    print(f"Generated {len(logs)} log events.")

if __name__ == "__main__":
    generate_logs()