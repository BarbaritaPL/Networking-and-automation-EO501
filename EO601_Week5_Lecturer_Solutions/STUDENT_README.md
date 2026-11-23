# EO601 Enterprise Networking – Week 5: Network Security Principles
## Python demonstrations and practical activities

Dr Sajjad Hussain · University of Brighton · 5 November 2026

All scripts use **standard-library Python only** (Python 3.8 or newer). Nothing to install, no real passwords, no live devices. Every IP address and log record is made up. External addresses use the documentation ranges `203.0.113.0/24` and `198.51.100.0/24`, which are reserved for examples.

> These are **educational simulations**, not production security tools. They do not capture, scan or block any real network traffic.

### Folder contents

```
EO601_Week5_Python_Student/
├── README.md                          (this file)
├── demos/
│   ├── demo1_firewall_simulator.py    Demonstration 1
│   ├── demo2_login_detector.py        Demonstration 2
│   └── login_records.csv              sample input for Demo 2
└── activities/
    ├── activity1_basic_firewall.py    Activity 1 starter (Beginner)
    ├── activity2_login_monitor.py     Activity 2 starter (Intermediate)
    ├── auth_log.txt                   sample input for Activity 2
    ├── activity3_network_audit.py     Activity 3 starter (Intermediate)
    └── university_network.json        sample input for Activity 3
```

### How to run

1. Unzip the folder and open it in VS Code (**File → Open Folder**).
2. Open a terminal in VS Code (**Terminal → New Terminal**).
3. Run a script, for example:

```
python demos/demo1_firewall_simulator.py
python demos/demo2_login_detector.py
python demos/demo2_login_detector.py --threshold 2
python activities/activity1_basic_firewall.py
```

On some Macs and Linux machines, type `python3` instead of `python`. Scripts find their input files automatically, so you can run them from any folder.

Every starter file **runs before you change anything**. It prints `TODO` or zero results, which tells you your setup works. Complete the numbered `TODO` comments in order and re-run after each one.

---

## Demonstration 1 – Firewall rule simulator

`demos/demo1_firewall_simulator.py` stores simulated packets in a list, checks each packet's source IP, destination IP, protocol and port against an ordered rule list, and prints ALLOW or DENY. The first matching rule wins; if no rule matches, the packet is denied (implicit deny). The `ipaddress` module checks whether an address belongs to a subnet, e.g. `10.10.20.15` is inside `10.10.0.0/16`.

Try this: move rule 1 (the block list) to the bottom of `RULES` and run again. What happens to packet 6, and why?

## Demonstration 2 – Suspicious login detection

`demos/demo2_login_detector.py` reads `login_records.csv`, counts failed logins per source IP with `collections.Counter`, flags any IP whose failures reach the threshold (default 3, change it with `--threshold`), and warns when a flagged IP later logs in successfully. Real organisations do this at scale with a SIEM (Security Information and Event Management) system.

---

## Activity 1 – Basic firewall rules (Beginner)

**Problem.** Complete `check_packet(src_ip, port)` in `activities/activity1_basic_firewall.py` so that every packet gets an ALLOW or DENY decision with a reason.

**Learning outcome.** Explain and implement ordered firewall rules: first match wins, and default deny.

**Rules, in order:**
1. Source IP in `BLOCKED_IPS` → DENY
2. Port 22 (SSH) from anyone except `ADMIN_IP` → DENY
3. Port in `ALLOWED_PORTS` (22, 53, 443) → ALLOW
4. Anything else → DENY (default deny)

**Sample input.** The `PACKETS` list at the top of the file (8 packets as `(source IP, port)` tuples).

**Steps.**
1. Run the starter and confirm every line says `TODO`.
2. Complete TODO 1 (block list) and re-run: two packets should now say DENY.
3. Complete TODO 2 (SSH admin-only) and TODO 3 (allowed ports).
4. Complete TODO 4 (default deny) and TODO 5 (count allowed packets).
5. Compare your output with the expected output below.

**Expected output**

```
Activity 1 - Basic Firewall Rules
----------------------------------------------------------------------
10.10.20.15      port 443   -> ALLOW  (port 443 (HTTPS) is permitted)
10.10.20.15      port 23    -> DENY   (port 23 is not in the allowed list (default deny))
198.51.100.23    port 443   -> DENY   (source IP is on the block list)
10.10.70.8       port 22    -> ALLOW  (port 22 (SSH) is permitted)
10.10.20.40      port 22    -> DENY   (SSH is only allowed from the admin workstation)
10.10.30.12      port 53    -> ALLOW  (port 53 (DNS) is permitted)
203.0.113.99     port 53    -> DENY   (source IP is on the block list)
10.10.30.12      port 3389  -> DENY   (port 3389 is not in the allowed list (default deny))
----------------------------------------------------------------------
3 allowed, 5 denied
```

**Extension tasks (optional).**
- Read the packets from a CSV file instead of the list (use the `csv` module).
- Block a whole subnet such as `198.51.100.0/24` using `ipaddress.ip_network`.
- Add a protocol field (`tcp`/`udp`) and only allow DNS on UDP.

---

## Activity 2 – Login security monitor (Intermediate)

**Problem.** `activities/auth_log.txt` contains simulated logins from the VPN, VLE and SSH servers. Report every source IP with **4 or more** failed attempts.

**Learning outcome.** Parse log data safely, count events per key with a dictionary, and turn accounting records into a simple security alert.

**Sample input** (one valid line, plus comments and one corrupted line in the file):

```
2026-11-05 10:15:02 vpn FAIL user=admin src=203.0.113.10
```

**Steps.**
1. Run the starter: it shows `Valid records: 0` because `parse_line()` is not finished.
2. Complete TODO 1 and TODO 2 in `parse_line()`. Re-run: you should see 24 valid records and 1 skipped line.
3. Complete TODO 3 in `count_failures()`.
4. Complete TODO 4 in `find_suspicious()` (filter by threshold, then sort highest first).
5. Compare with the expected output.

**Expected output**

```
Activity 2 - Login Security Monitor
--------------------------------------------------
Valid records: 24   Skipped lines: 1
Threshold: 4 failed attempts

Failures per IP:
  203.0.113.10     6
  198.51.100.200   6
  10.10.30.44      4
  10.10.20.90      2
  10.10.70.8       1

SUSPICIOUS IP ADDRESSES:
  [!] 203.0.113.10     6 failed attempts
  [!] 198.51.100.200   6 failed attempts
  [!] 10.10.30.44      4 failed attempts
```

**Discussion.** `10.10.30.44` failed four times and then succeeded, all with one username, from inside the staff network. Is that an attack or a member of staff who forgot their password? What extra information would help you decide?

**Extension tasks (optional).**
- Only flag an IP when it has 5 failures within 60 seconds (use `datetime.strptime`).
- Show which usernames each flagged IP tried.
- Save the report to `report.csv`.

---

## Activity 3 – University network security audit (Intermediate)

**Problem.** `activities/university_network.json` describes a campus network with eight zones (student, staff, admin_servers, vle_servers, guest, it_ops, network_devices, internet) and 13 firewall rules. Several rules were added in a hurry and are insecure. Write five checks that find them.

**Learning outcome.** Apply CIA, least privilege and segmentation to a realistic configuration, and automate a basic security review with Python and JSON.

| Check | Insecure when… | Severity |
|---|---|---|
| `check_guest_isolation` | source is `guest` and destination is not `internet` | HIGH |
| `check_any_source_to_sensitive` | source is `any` and destination is in `SENSITIVE_ZONES` | HIGH |
| `check_least_privilege` | source is `student` and destination is in `SENSITIVE_ZONES` | HIGH |
| `check_insecure_protocols` | port is in `INSECURE_PORTS` (FTP, Telnet, HTTP) and destination is not `internet` | MEDIUM |
| `check_any_port` | port is `any` and destination is not `internet` | MEDIUM |

**Sample input** (one rule from the JSON file):

```json
{"id": "R06", "action": "allow", "src": "guest", "dst": "staff", "protocol": "tcp", "port": 445, "comment": "Visitors print via staff file share"}
```

**Steps.**
1. Open the JSON file and read the rules yourself first. Which ones look wrong?
2. Run the starter: it reports `Findings: 0`.
3. Complete TODO 1 – TODO 5, one check at a time, re-running after each.
4. Complete TODO 6 so deny rules are skipped (the final default-deny rule must not be flagged).
5. Compare with the expected output.

**Expected output**

```
Security audit: University of Example - Main Campus (simulated)
==========================================================================
Rules examined: 13

[HIGH  ] R05  student -> admin_servers tcp/3306
          Students can reach 'admin_servers' (breaks least privilege)
[HIGH  ] R06  guest -> staff tcp/445
          Guest network can reach internal zone 'staff'
[MEDIUM] R08  it_ops -> network_devices tcp/23
          Unencrypted protocol Telnet (port 23) allowed
[HIGH  ] R09  any -> admin_servers tcp/3389
          Any source (including the internet) can reach 'admin_servers'
[MEDIUM] R10  staff -> network_devices any/any
          All ports open to internal zone 'network_devices'
[HIGH  ] R12  guest -> vle_servers tcp/80
          Guest network can reach internal zone 'vle_servers'
[MEDIUM] R12  guest -> vle_servers tcp/80
          Unencrypted protocol HTTP (port 80) allowed

--------------------------------------------------------------------------
Findings: 7  (HIGH: 4, MEDIUM: 3)
Rules needing review: R05, R06, R08, R09, R10, R12
```

**Extension tasks (optional).**
- For every finding, print a suggested safer rule (e.g. replace Telnet with SSH on port 22).
- Check that the last rule is a default deny, and report if it is missing.
- Detect *shadowed* rules: a rule that can never match because an earlier rule already covers it.
- Save the findings to `audit_report.json` with `json.dump`.
