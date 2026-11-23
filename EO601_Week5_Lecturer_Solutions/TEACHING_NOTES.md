# EO601 Week 5 – Lecturer solutions and teaching notes

Dr Sajjad Hussain · Network Security Principles · 5 November 2026

## Contents

```
EO601_Week5_Lecturer_Solutions/
├── TEACHING_NOTES.md               (this file)
├── demos/                          Demo 1 and Demo 2 (same as student copies) + login_records.csv
├── solutions/
│   ├── activity1_solution.py
│   ├── activity2_solution.py   + auth_log.txt
│   └── activity3_solution.py   + university_network.json
└── expected_outputs/              Captured output of every demo and solution
```

All solutions were run with Python 3.13 and use only the standard library. Run them the same way as the student files, e.g. `python solutions/activity3_solution.py`.

## Suggested flow for the 2-hour session

1. Slides 1–16: principles, with the on-slide questions as quick discussion points. Animated builds are on slides 5 (CIA), 9 (AAA), 11 (defence in depth), 12 (firewall decision), 14 (segmentation) and 15 (TLS handshake); press the spacebar to advance each step.
2. Slides 17–18: run both demos live in VS Code. Ask students to predict Demo 1 decisions from the slide 12 rule table before running it.
3. Slide 19: independent practical work. Everyone starts with Activity 1; stronger students move to 2 and 3.
4. Slide 20: summary, quick check (answers are in the speaker notes), Blackboard quiz.

## Demonstration notes

**Demo 1.** A good live change: move rule 1 (block list) below rule 2, then re-run. Packet 6 from `198.51.100.77` becomes ALLOW because rule 2 now matches first. This is the same idea as quiz question 6. Point out that `ipaddress` makes subnet matching one line.

**Demo 2.** Run with `--threshold 3` (default) and then `--threshold 2`. At 2, `10.10.20.58` (l.chen, two typos then success) is flagged: a useful way to discuss false positives. `198.51.100.23` succeeds after three failures, which is the most serious alert in the file.

## Activity 1 – marking notes

- The common mistake is checking the allowed ports before the SSH rule. Then `10.10.20.40` on port 22 becomes ALLOW. Ask students why the order matters.
- `203.0.113.99` on port 53 must be DENY even though DNS is allowed: the block list comes first.
- Correct summary: **3 allowed, 5 denied**.

## Activity 2 – marking notes

- Correct parsing gives **24 valid records, 1 skipped line** (comments are not counted as skipped).
- Flagged IPs: `203.0.113.10` (6), `198.51.100.200` (6), `10.10.30.44` (4). `10.10.20.90` (2) and `10.10.70.8` (1) are below the threshold.
- Note that `203.0.113.10` reaches 6 only because of the final record at 10:26:44. Students attempting the 60-second-window extension will find that it has 5 failures in its first burst, so it is still flagged; `198.51.100.200` has 6 within 5 seconds.
- Discussion answer: `10.10.30.44` is an internal staff address using one username, so it may be a forgetful user. Look at the time pattern, check with the user, and confirm MFA.

## Activity 3 – marking notes

Expected: **7 findings (HIGH 4, MEDIUM 3) on rules R05, R06, R08, R09, R10, R12.**

| Rule | Problem | Better rule |
|---|---|---|
| R05 | Students reach the admin database on 3306 | Remove it, or host the project database in a separate student-project zone |
| R06 | Guest Wi-Fi reaches the staff file share | Provide a guest print service; guest → internet only |
| R08 | Telnet to switches sends passwords in clear text | SSH (TCP 22) from it_ops only |
| R09 | RDP to admin servers from any source, including the internet | Supplier connects via VPN, then RDP from a named jump host |
| R10 | Staff have every port to network devices | Remove; only it_ops manage devices |
| R12 | Guest reaches the VLE over plain HTTP | HTTPS only, through the public VLE address |

R11 (students → internet on any port) is deliberately *not* flagged by the five checks. It is a good discussion point for strong students: is "any port to the internet" acceptable? Many organisations restrict outbound traffic too.

## Answers to on-slide questions

| Slide | Question | Answer |
|---|---|---|
| 2 | Most harm if offline for a day? | Open discussion; hospital is usually chosen – availability can be a safety issue |
| 6 | Is a Wi-Fi password enough? | No – everyone with the password shares the network; end-to-end encryption (TLS) is still needed |
| 8 | Firewall blocks 443 for everyone | Availability |
| 9 | Cannot open another module's gradebook | Authorisation |
| 10 | Backup script permissions | Read-only, limited to the devices it backs up, with an expiring token |
| 13 | Can students reach 10.10.30.0/24? | Yes, via line 40 – probably unintended; add a deny for the staff subnet |
| 16 | Token found on public GitHub | Revoke/rotate it immediately; deleting the commit is not enough |
| 20 | Quick check 1–4 | Confidentiality; authentication; denied by implicit deny; environment variable or secrets vault |

## Accuracy notes

- `198.51.100.0/24` and `203.0.113.0/24` are RFC 5737 documentation ranges; `10.10.0.0/16` is private (RFC 1918) address space.
- The TLS handshake on slide 15 is simplified on purpose; TLS 1.3 combines key exchange into the first two messages.
- The hash values on slide 7 are the real SHA-256 digests of the two strings shown and can be reproduced with the snippet on the slide.
- The ACL on slide 13 uses valid Cisco IOS named extended ACL syntax applied inbound on an SVI. It is shown for recognition only; there is no Packet Tracer activity.
