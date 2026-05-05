# System Architecture & Data Flow

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        whole_code.py                            │
│                                                                 │
│  ┌──────────────┐     ┌──────────────────────────────────────┐  │
│  │ snort_rules  │────▶│  Rule Parser                         │  │
│  │    .conf     │     │  parse_snort_rules()                 │  │
│  └──────────────┘     │  parse_options()                     │  │
│                       └──────────────┬───────────────────────┘  │
│                                      │ parsed_rules[]            │
│                                      ▼                           │
│  ┌──────────────┐     ┌──────────────────────────────────────┐  │
│  │  Network     │     │  Packet Capture Engine               │  │
│  │  Interface   │────▶│  live_capture()                      │  │
│  │  or PCAP     │     │  pyshark.LiveCapture / FileCapture   │  │
│  └──────────────┘     └──────────────┬───────────────────────┘  │
│                                      │ packet (PyShark obj)      │
│                                      ▼                           │
│                       ┌──────────────────────────────────────┐  │
│                       │  packet_handler() closure (in main)  │  │
│                       │                                       │  │
│                       │  Extract: protocol, IPs, ports,       │  │
│                       │          payload bytes                │  │
│                       │                                       │  │
│                       │  ┌─────────────────────────────────┐ │  │
│                       │  │  Rule Matching Engine           │ │  │
│                       │  │                                 │ │  │
│                       │  │  match_protocol()               │ │  │
│                       │  │  match_direction()       AND    │ │  │
│                       │  │  match_address() x2      logic  │ │  │
│                       │  │  match_port() x2                │ │  │
│                       │  │  match_content()                │ │  │
│                       │  │  check_threshold()              │ │  │
│                       │  │  match_packet_to_rule()         │ │  │
│                       │  └────────────────┬────────────────┘ │  │
│                       │                   │ MATCH             │  │
│                       └───────────────────┼───────────────────┘  │
│                                           ▼                      │
│              ┌────────────────────────────────────────────────┐  │
│              │              Alert Dispatcher                  │  │
│              │                                                │  │
│              │  ┌──────────┐ ┌──────────┐ ┌───────────────┐  │  │
│              │  │ Console  │ │alert.log │ │  packets.db   │  │  │
│              │  │  print   │ │run_alert │ │  SQLite INSERT│  │  │
│              │  └──────────┘ └──────────┘ └───────────────┘  │  │
│              │                    ┌──────────────────────┐    │  │
│              │                    │  Email (SMTP/Gmail)  │    │  │
│              │                    │  send_alert_email()  │    │  │
│              │                    └──────────────────────┘    │  │
│              └────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow — Step by Step

### Phase 1: Startup

```
Program starts
    │
    ├── sqlite3.connect('packets.db')       ← DB connection opened at module load
    │       CREATE TABLE IF NOT EXISTS packets (...)
    │
    └── main()
            │
            └── parse_snort_rules('snort_rules.conf')
                    │
                    ├── Read file line by line
                    ├── Split each line into 7 header fields
                    ├── parse_options() → extract key:value option pairs
                    └── Return list of rule dicts
```

### Phase 2: Packet Capture

```
live_capture(packet_handler)
    │
    ├── argparse: parse -i / -o / -p / -n / -s / -v
    │
    ├── If -o: pyshark.FileCapture(file)
    │   If -i: pyshark.LiveCapture(interface, output_file)
    │
    └── For each packet in capture:
            │
            ├── Apply protocol filter (if -p specified)
            └── Call packet_handler(packet)
```

### Phase 3: Packet Analysis

```
packet_handler(packet)
    │
    ├── Extract timestamp     → time.asctime()
    ├── Extract protocol      → packet.highest_layer (strip _raw suffix)
    ├── Extract src/dst IP    → packet['IP'].src / .dst
    ├── Extract src/dst port  → layer.srcport / .dstport
    ├── Extract payload       → packet.tcp / udp .get('*.payload')
    │       └── bytes.fromhex(payload.replace(":", ""))
    │
    ├── Print formatted console row
    │
    └── For each rule in parsed_rules:
            │
            ├── match_protocol()     ──┐
            ├── match_direction()      │ Header checks
            ├── match_address() x2    │ (fast path — no payload needed)
            ├── match_port() x2     ──┘
            │
            └── If header matches:
                    │
                    ├── 'content'   in rule → match_content()
                    ├── 'threshold' in rule → check_threshold()
                    └── 'flow'      in rule → match_packet_to_rule()
                            │
                            └── If ALL conditions pass → ALERT
```

### Phase 4: Alert Dispatch

```
ALERT triggered
    │
    ├── Console:    print("Alert: ", msg)
    │
    ├── Log file:   run_alert() → append to alert.log
    │                   Format: "msg\nTime: ..., Protocol: ..., Src: ..., Dst: ..."
    │
    ├── Database:   cursor.execute(INSERT INTO packets VALUES (...))
    │               conn.commit()
    │
    └── Email:      send_alert_email(rule, matched_values)
                        └── smtplib.SMTP → STARTTLS → login → sendmail
```

---

## Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| Rule Parser | `whole_code.py` | Load and structure detection rules from file |
| Capture Engine | `whole_code.py` + PyShark | Open packet source, iterate packets |
| Packet Handler | `whole_code.py` | Extract fields, coordinate rule evaluation |
| Match Functions | `whole_code.py` | Individual rule condition checks |
| Alert Dispatcher | `whole_code.py` | Fan out alerts to all configured channels |
| Database | `packets.db` | Persistent record of every matched packet |
| Log File | `alert.log` | Human-readable alert history |
| Rules Config | `snort_rules.conf` | Declarative threat detection signatures |

---

## Output Files

| File | Format | Created By | Contents |
|------|--------|-----------|----------|
| `alert.log` | Plain text | `run_alert()` | One entry per matched packet |
| `packets.db` | SQLite3 | `main()` / cursor | Table: `packets` with 6 columns |

---

## Dependency Graph

```
whole_code.py
├── pyshark          (pip)
│   └── tshark       (system — apt/brew)
├── psutil           (pip — imported, unused)
├── sqlite3          (stdlib)
├── smtplib          (stdlib)
├── argparse         (stdlib)
├── datetime         (stdlib)
└── snort_rules.conf (local file, must be present at runtime)
```
