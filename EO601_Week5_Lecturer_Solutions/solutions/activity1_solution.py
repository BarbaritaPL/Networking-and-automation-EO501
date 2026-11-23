"""
EO601 Week 5 - Activity 1: Basic Firewall Rules (Beginner)
LECTURER SOLUTION

Decision order (first match wins):
  1. Source IP on the block list            -> DENY
  2. SSH (port 22) from anyone except admin -> DENY
  3. Port in the allowed list               -> ALLOW
  4. Anything else                          -> DENY (default deny)
"""

BLOCKED_IPS = {"198.51.100.23", "203.0.113.99"}   # known bad addresses
ADMIN_IP = "10.10.70.8"                           # IT admin workstation
ALLOWED_PORTS = {22: "SSH", 53: "DNS", 443: "HTTPS"}

# Sample input: (source IP, destination port)
PACKETS = [
    ("10.10.20.15", 443),
    ("10.10.20.15", 23),
    ("198.51.100.23", 443),
    ("10.10.70.8", 22),
    ("10.10.20.40", 22),
    ("10.10.30.12", 53),
    ("203.0.113.99", 53),
    ("10.10.30.12", 3389),
]


def check_packet(src_ip, port):
    """Return a (decision, reason) tuple for one packet."""
    if src_ip in BLOCKED_IPS:
        return "DENY", "source IP is on the block list"
    if port == 22 and src_ip != ADMIN_IP:
        return "DENY", "SSH is only allowed from the admin workstation"
    if port in ALLOWED_PORTS:
        return "ALLOW", f"port {port} ({ALLOWED_PORTS[port]}) is permitted"
    return "DENY", f"port {port} is not in the allowed list (default deny)"


def main():
    print("Activity 1 - Basic Firewall Rules")
    print("-" * 70)
    allowed = 0
    for src_ip, port in PACKETS:
        decision, reason = check_packet(src_ip, port)
        if decision == "ALLOW":
            allowed += 1
        print(f"{src_ip:<16} port {port:<5} -> {decision:<5}  ({reason})")
    print("-" * 70)
    print(f"{allowed} allowed, {len(PACKETS) - allowed} denied")


if __name__ == "__main__":
    main()
