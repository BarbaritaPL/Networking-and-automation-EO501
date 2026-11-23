"""
EO601 Enterprise Networking - Week 5: Network Security Principles
Demonstration 2: Detecting Suspicious Login Attempts

WHAT THIS SCRIPT DOES
---------------------
Servers, VPN gateways and network devices write a log entry every time
someone tries to log in. Many failed attempts from the same IP address in a
short time is a common sign of password guessing (a "brute-force" attack).

This script:
  1. Reads simulated login records from login_records.csv
  2. Counts FAILED attempts for each source IP address
  3. Flags any IP whose failures reach a configurable threshold
  4. Warns when a flagged IP later logs in successfully
     (the guess may have worked - investigate that account!)
  5. Prints a simple security report

IMPORTANT: This is an educational simulation using made-up records.
Real organisations use dedicated tools (e.g. a SIEM - Security Information
and Event Management system) that do this at much larger scale.

Run:  python demo2_login_detector.py
      python demo2_login_detector.py --threshold 2
      python demo2_login_detector.py --file my_logs.csv
"""

import argparse                 # read options from the command line
import csv                      # read comma-separated files
from collections import Counter, defaultdict
from pathlib import Path        # build file paths that work on any OS

DEFAULT_LOG = Path(__file__).with_name("login_records.csv")


def read_records(path):
    """Read the CSV file and return a list of dictionaries (one per row)."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def analyse(records, threshold):
    """Count failures per IP and decide which IPs are suspicious."""
    failures = Counter()                 # e.g. {"203.0.113.66": 7, ...}
    usernames = defaultdict(set)         # which usernames each IP tried
    success_after_fail = set()           # IPs that succeeded after failing

    for row in records:
        ip = row["source_ip"]
        usernames[ip].add(row["username"])
        if row["result"] == "FAIL":
            failures[ip] += 1
        elif row["result"] == "SUCCESS" and failures[ip] >= threshold:
            success_after_fail.add(ip)

    flagged = {ip: n for ip, n in failures.items() if n >= threshold}
    return failures, flagged, usernames, success_after_fail


def print_report(records, threshold, failures, flagged, usernames, success_after_fail):
    total_fail = sum(failures.values())
    print("=" * 64)
    print(" EO601 Week 5 - Login Security Report (educational simulation)")
    print("=" * 64)
    print(f"Records analysed : {len(records)}")
    print(f"Failed logins    : {total_fail}")
    print(f"Alert threshold  : {threshold} failed attempts per IP")
    print()
    print("Failed attempts per source IP")
    print("-" * 64)
    for ip, count in failures.most_common():
        status = "FLAGGED" if ip in flagged else "ok"
        word = "failure " if count == 1 else "failures"
        print(f"  {ip:<16}{count:>3} {word}   {status}")
    print()
    if not flagged:
        print("No IP addresses reached the threshold.")
        return
    print("Security alerts")
    print("-" * 64)
    for ip, count in sorted(flagged.items(), key=lambda item: -item[1]):
        names = ", ".join(sorted(usernames[ip]))
        print(f"  [ALERT] {ip} - {count} failures, usernames tried: {names}")
        if len(usernames[ip]) > 1:
            print("          Several usernames tried: looks like password guessing.")
        if ip in success_after_fail:
            print("          WARNING: a later login from this IP SUCCEEDED."
                  " Check that account.")
    print()
    print("Suggested next steps: block or rate-limit flagged IPs at the firewall,")
    print("lock or reset affected accounts, and confirm MFA is enabled.")


def main():
    parser = argparse.ArgumentParser(description="Detect repeated failed logins.")
    parser.add_argument("--threshold", type=int, default=3,
                        help="failed attempts before an IP is flagged (default 3)")
    parser.add_argument("--file", default=DEFAULT_LOG,
                        help="CSV log file (default login_records.csv)")
    args = parser.parse_args()

    records = read_records(args.file)
    results = analyse(records, args.threshold)
    print_report(records, args.threshold, *results)


if __name__ == "__main__":
    main()
