"""
EO601 Enterprise Networking - Week 5: Network Security Principles
Demonstration 1: Simple Firewall Rule Simulator

WHAT THIS SCRIPT DOES
---------------------
A firewall inspects each packet and compares it against an ORDERED list of
rules. The FIRST rule that matches decides the outcome (ALLOW or DENY).
If no rule matches, the packet is denied (the "implicit deny" rule).

This script simulates that process for a small university network:

    10.10.20.0/24  Student devices
    10.10.30.0/24  Academic staff
    10.10.40.0/24  Administration servers (finance, student records)
    10.10.50.10    Virtual Learning Environment (VLE) web server
    10.10.0.53     Internal DNS server
    10.10.70.0/24  IT operations team

External addresses use the documentation ranges 203.0.113.0/24 and
198.51.100.0/24 (RFC 5737), which are reserved for examples like this one.

IMPORTANT: This is an educational simulation, not a real firewall.
It does not capture or block any real network traffic.

Run:  python demo1_firewall_simulator.py
"""

import ipaddress  # standard library: understands IP addresses and subnets

# ---------------------------------------------------------------------------
# 1. Firewall rules - checked from top to bottom, first match wins.
#    "any" means the field is not checked.
# ---------------------------------------------------------------------------
RULES = [
    {"id": 1, "action": "DENY",  "src": "198.51.100.0/24", "dst": "any",
     "protocol": "any", "port": "any",
     "reason": "Known malicious external range (block list)"},
    {"id": 2, "action": "ALLOW", "src": "any", "dst": "10.10.50.10/32",
     "protocol": "tcp", "port": 443,
     "reason": "HTTPS to the VLE web server"},
    {"id": 3, "action": "ALLOW", "src": "10.10.70.0/24", "dst": "10.10.40.0/24",
     "protocol": "tcp", "port": 22,
     "reason": "SSH to admin servers - IT operations only"},
    {"id": 4, "action": "ALLOW", "src": "10.10.0.0/16", "dst": "10.10.0.53/32",
     "protocol": "udp", "port": 53,
     "reason": "Internal DNS lookups"},
    {"id": 5, "action": "ALLOW", "src": "10.10.70.0/24", "dst": "any",
     "protocol": "icmp", "port": "any",
     "reason": "Ping (ICMP) for IT troubleshooting"},
]

# ---------------------------------------------------------------------------
# 2. Simulated packets. A real packet holds much more information; we keep
#    only the fields our rules need.
# ---------------------------------------------------------------------------
PACKETS = [
    {"src": "10.10.20.15",   "dst": "10.10.50.10", "protocol": "tcp",  "port": 443,
     "note": "Student opens the VLE"},
    {"src": "10.10.20.15",   "dst": "10.10.40.5",  "protocol": "tcp",  "port": 22,
     "note": "Student tries SSH to an admin server"},
    {"src": "10.10.70.8",    "dst": "10.10.40.5",  "protocol": "tcp",  "port": 22,
     "note": "IT engineer manages an admin server"},
    {"src": "203.0.113.45",  "dst": "10.10.50.10", "protocol": "tcp",  "port": 443,
     "note": "Student working from home uses the VLE"},
    {"src": "203.0.113.45",  "dst": "10.10.50.10", "protocol": "tcp",  "port": 23,
     "note": "Telnet attempt from the internet"},
    {"src": "198.51.100.77", "dst": "10.10.50.10", "protocol": "tcp",  "port": 443,
     "note": "Block-listed address tries the VLE"},
    {"src": "10.10.30.12",   "dst": "10.10.0.53",  "protocol": "udp",  "port": 53,
     "note": "Lecturer's laptop resolves a website name"},
    {"src": "10.10.70.8",    "dst": "10.10.30.12", "protocol": "icmp", "port": None,
     "note": "IT engineer pings a staff laptop"},
    {"src": "10.10.20.15",   "dst": "10.10.40.20", "protocol": "tcp",  "port": 3306,
     "note": "Student connects to the finance database"},
]


def ip_matches(packet_ip, rule_value):
    """Return True if packet_ip is inside the rule's network (or rule is 'any')."""
    if rule_value == "any":
        return True
    ip = ipaddress.ip_address(packet_ip)
    return ip in ipaddress.ip_network(rule_value)


def field_matches(packet_value, rule_value):
    """Simple equality check that also understands 'any'."""
    return rule_value == "any" or packet_value == rule_value


def check_packet(packet, rules):
    """Return (action, rule) for the FIRST matching rule, or the implicit deny."""
    for rule in rules:
        if (ip_matches(packet["src"], rule["src"])
                and ip_matches(packet["dst"], rule["dst"])
                and field_matches(packet["protocol"], rule["protocol"])
                and field_matches(packet["port"], rule["port"])):
            return rule["action"], rule
    # No rule matched: deny by default. This is the safest choice.
    return "DENY", {"id": None, "reason": "Implicit deny (no rule matched)"}


def main():
    print("=" * 78)
    print(" EO601 Week 5 - Firewall Rule Simulator (educational simulation)")
    print("=" * 78)
    print(f"{'#':<3}{'Source':<16}{'Destination':<14}{'Proto':<6}{'Port':<6}"
          f"{'Result':<7}Rule / reason")
    print("-" * 78)

    allowed = denied = 0
    for number, packet in enumerate(PACKETS, start=1):
        action, rule = check_packet(packet, RULES)
        port = packet["port"] if packet["port"] is not None else "-"
        label = f"R{rule['id']}" if rule["id"] is not None else "Default"
        print(f"{number:<3}{packet['src']:<16}{packet['dst']:<14}"
              f"{packet['protocol']:<6}{port!s:<6}{action:<7}"
              f"{label}: {rule['reason']}")
        print(f"{'':<3}  ({packet['note']})")
        if action == "ALLOW":
            allowed += 1
        else:
            denied += 1

    print("-" * 78)
    print(f"Summary: {allowed} allowed, {denied} denied, {len(PACKETS)} packets checked")
    print()
    print("Why this helps: only traffic that a rule explicitly permits gets through.")
    print("Everything else - unknown ports, unexpected sources - is denied by default.")


if __name__ == "__main__":
    main()
