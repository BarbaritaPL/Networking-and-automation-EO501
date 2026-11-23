"""
EO601 Week 5 - Activity 2: Login Security Monitor (Intermediate)
LECTURER SOLUTION

Reads auth_log.txt, counts failed logins per source IP and reports any IP
whose failures reach THRESHOLD. Comment lines (#), blank lines and
malformed lines are skipped safely.
"""

from pathlib import Path

LOG_FILE = Path(__file__).with_name("auth_log.txt")
THRESHOLD = 4


def parse_line(line):
    """Turn one log line into a dictionary, or return None if it is not valid.

    Example input:
      2026-11-05 10:15:02 vpn FAIL user=admin src=203.0.113.10
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if len(parts) != 6 or not parts[4].startswith("user=") or not parts[5].startswith("src="):
        return None
    return {
        "time": f"{parts[0]} {parts[1]}",
        "service": parts[2],
        "result": parts[3],
        "user": parts[4].split("=", 1)[1],
        "ip": parts[5].split("=", 1)[1],
    }


def read_log(path):
    records, skipped = [], 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            record = parse_line(line)
            if record:
                records.append(record)
            elif line.strip() and not line.startswith("#"):
                skipped += 1
    return records, skipped


def count_failures(records):
    """Return a dictionary {ip: number_of_failed_logins}."""
    counts = {}
    for r in records:
        if r["result"] == "FAIL":
            counts[r["ip"]] = counts.get(r["ip"], 0) + 1
    return counts


def find_suspicious(counts, threshold):
    """Return a list of (ip, count) at or above threshold, highest first."""
    suspicious = [(ip, n) for ip, n in counts.items() if n >= threshold]
    return sorted(suspicious, key=lambda item: item[1], reverse=True)


def main():
    records, skipped = read_log(LOG_FILE)
    counts = count_failures(records)
    suspicious = find_suspicious(counts, THRESHOLD)

    print("Activity 2 - Login Security Monitor")
    print("-" * 50)
    print(f"Valid records: {len(records)}   Skipped lines: {skipped}")
    print(f"Threshold: {THRESHOLD} failed attempts")
    print()
    print("Failures per IP:")
    for ip, n in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        print(f"  {ip:<16} {n}")
    print()
    if suspicious:
        print("SUSPICIOUS IP ADDRESSES:")
        for ip, n in suspicious:
            print(f"  [!] {ip:<16} {n} failed attempts")
    else:
        print("No suspicious IP addresses found.")


if __name__ == "__main__":
    main()
