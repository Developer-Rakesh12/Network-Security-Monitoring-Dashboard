"""Analyze an offline CSV sample. No packet capture or network probing is performed."""
import csv
from pathlib import Path
from collections import Counter, defaultdict

SAMPLE_FILE = Path(__file__).parent / "data" / "sample_network_traffic.csv"
REQUIRED = {"timestamp", "source", "destination", "protocol", "bytes"}


def load_and_analyze(source):
    reader = csv.DictReader(source)
    fields = set(reader.fieldnames or [])
    missing = REQUIRED - fields
    if missing:
        raise ValueError("CSV is missing required columns: " + ", ".join(sorted(missing)))

    events = []
    for row in reader:
        try:
            size = int(row["bytes"])
            if size < 0:
                raise ValueError
        except (ValueError, TypeError):
            continue
        events.append({
            "timestamp": row["timestamp"],
            "source": row["source"],
            "destination": row["destination"],
            "protocol": row["protocol"].upper(),
            "bytes": size,
            "status": "NORMAL",
            "reason": ""
        })

    if not events:
        raise ValueError("No valid traffic rows were found in the CSV.")

    protocol_counts = Counter(e["protocol"] for e in events)
    source_counts = Counter(e["source"] for e in events)
    destination_counts = Counter(e["destination"] for e in events)
    total_bytes = sum(e["bytes"] for e in events)
    avg_bytes = total_bytes / len(events)

    # Educational heuristics applied to supplied records only.
    # These are indicators for review, not proof of malicious activity.
    for event in events:
        reasons = []
        if event["bytes"] > max(50000, avg_bytes * 4):
            reasons.append("Unusually large record compared with sample average")
        if source_counts[event["source"]] >= max(8, len(events) * 0.35):
            reasons.append("Source appears frequently in this sample")
        if event["protocol"] not in {"TCP", "UDP", "ICMP", "DNS", "HTTPS", "HTTP"}:
            reasons.append("Unrecognized protocol label in sample")
        if reasons:
            event["status"] = "REVIEW"
            event["reason"] = "; ".join(reasons)

    flagged = [e for e in events if e["status"] == "REVIEW"]
    hourly = defaultdict(int)
    for event in events:
        key = event["timestamp"][:13] if len(event["timestamp"]) >= 13 else event["timestamp"]
        hourly[key] += 1

    return {
        "total_events": len(events),
        "total_bytes": total_bytes,
        "average_bytes": round(avg_bytes, 2),
        "flagged_count": len(flagged),
        "protocol_labels": list(protocol_counts.keys()),
        "protocol_counts": dict(protocol_counts),
        "top_sources": source_counts.most_common(5),
        "top_destinations": destination_counts.most_common(5),
        "timeline_labels": list(hourly.keys()),
        "timeline_values": list(hourly.values()),
        "events": events,
        "note": "Offline sample analysis only. REVIEW flags are simple educational heuristics, not confirmed attacks."
    }
