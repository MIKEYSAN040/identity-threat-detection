import boto3
import json
from datetime import datetime, timedelta

def fetch_cloudtrail_logs(region="us-east-1", hours=24, output_path="data/cloudtrail_logs.json"):
    client = boto3.client("cloudtrail", region_name=region)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)

    print(f"Fetching CloudTrail events from {start_time} to {end_time}...")

    events = []
    paginator = client.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"MaxItems": 1000}
    )

    for page in page_iterator:
        for event in page.get("Events", []):
            raw = json.loads(event.get("CloudTrailEvent", "{}"))

            username = (
                raw.get("userIdentity", {}).get("userName") or
                raw.get("userIdentity", {}).get("sessionContext", {})
                   .get("sessionIssuer", {}).get("userName") or
                raw.get("userIdentity", {}).get("type", "Unknown")
            )
            source_ip = raw.get("sourceIPAddress", "Unknown")
            event_name = raw.get("eventName", "Unknown")
            event_time = raw.get("eventTime", datetime.utcnow().isoformat())
            error = raw.get("errorCode", None)

            normalized = {
                "eventTime": event_time,
                "username": username,
                "eventName": event_name,
                "sourceIPAddress": source_ip,
                "location": {"city": "AWS", "country": "Cloud", "lat": 0.0, "lon": 0.0},
                "status": "Failure" if error else "Success",
                "userAgent": raw.get("userAgent", "aws-internal")
            }
            events.append(normalized)

    events.sort(key=lambda x: x["eventTime"])

    with open(output_path, "w") as f:
        json.dump(events, f, indent=2)

    print(f"Fetched {len(events)} CloudTrail events saved to {output_path}")
    return events

if __name__ == "__main__":
    fetch_cloudtrail_logs()