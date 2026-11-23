"""
EO601 Week 5 - Activity 3: University Network Security Audit (Intermediate)
LECTURER SOLUTION

Loads university_network.json and audits every ALLOW rule against five
security checks. Each check returns a list of findings; a finding is a
dictionary with rule id, severity and a short explanation.
"""

import json
from pathlib import Path

CONFIG_FILE = Path(__file__).with_name("university_network.json")

SENSITIVE_ZONES = {"admin_servers", "network_devices"}
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP"}  # send data unencrypted


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def finding(rule, severity, issue):
    return {"rule": rule["id"], "severity": severity, "issue": issue,
            "summary": f"{rule['src']} -> {rule['dst']} {rule['protocol']}/{rule['port']}"}


# ---------------- Individual checks (each receives one ALLOW rule) ----------
def check_guest_isolation(rule):
    """Guest Wi-Fi should only reach the internet."""
    if rule["src"] == "guest" and rule["dst"] != "internet":
        return [finding(rule, "HIGH", f"Guest network can reach internal zone '{rule['dst']}'")]
    return []


def check_any_source_to_sensitive(rule):
    """Sensitive zones must never accept traffic from 'any' source."""
    if rule["src"] == "any" and rule["dst"] in SENSITIVE_ZONES:
        return [finding(rule, "HIGH", f"Any source (including the internet) can reach '{rule['dst']}'")]
    return []


def check_least_privilege(rule):
    """Students have no business reaching admin servers or network devices."""
    if rule["src"] == "student" and rule["dst"] in SENSITIVE_ZONES:
        return [finding(rule, "HIGH", f"Students can reach '{rule['dst']}' (breaks least privilege)")]
    return []


def check_insecure_protocols(rule):
    """Unencrypted protocols should not be used inside the network."""
    port = rule["port"]
    if port in INSECURE_PORTS and rule["dst"] != "internet":
        return [finding(rule, "MEDIUM", f"Unencrypted protocol {INSECURE_PORTS[port]} (port {port}) allowed")]
    return []


def check_any_port(rule):
    """'Any port' to an internal zone is far wider than needed."""
    if rule["port"] == "any" and rule["dst"] != "internet":
        return [finding(rule, "MEDIUM", f"All ports open to internal zone '{rule['dst']}'")]
    return []


CHECKS = [check_guest_isolation, check_any_source_to_sensitive, check_least_privilege,
          check_insecure_protocols, check_any_port]


def audit(rules):
    findings = []
    for rule in rules:
        if rule["action"] != "allow":
            continue                     # deny rules cannot open access
        for check in CHECKS:
            findings.extend(check(rule))
    return findings


def main():
    config = load_config(CONFIG_FILE)
    rules = config["rules"]
    findings = audit(rules)

    print(f"Security audit: {config['network']}")
    print("=" * 74)
    print(f"Rules examined: {len(rules)}")
    print()
    for f in findings:
        print(f"[{f['severity']:<6}] {f['rule']}  {f['summary']}")
        print(f"          {f['issue']}")
    print()
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    flagged = sorted({f["rule"] for f in findings})
    print("-" * 74)
    print(f"Findings: {len(findings)}  (HIGH: {high}, MEDIUM: {medium})")
    print(f"Rules needing review: {', '.join(flagged) if flagged else 'none'}")


if __name__ == "__main__":
    main()
