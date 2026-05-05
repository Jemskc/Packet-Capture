# Packet Capture & Intrusion Detection System

A Python-based network intrusion detection tool that captures live packets or reads PCAP files, matches them against Snort-style rules, and triggers multi-channel alerts — console, log file, SQLite database, and email.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Snort Rules](#snort-rules)
- [Output & Alerts](#output--alerts)
- [Email Configuration](#email-configuration)
- [Documentation](#documentation)
- [Disclaimer](#disclaimer)

---

## Overview

This tool provides two modes of operation:

| Mode | Flag | Description |
|------|------|-------------|
| Live Capture | `-i <interface>` | Capture packets in real time from a network interface |
| PCAP Analysis | `-o <file.pcap>` | Replay and analyze a saved `.pcap` or `.pcapng` file |

On each captured packet, the engine extracts the protocol, source/destination IPs and ports, and payload bytes — then evaluates them against a set of Snort-style detection rules. Any match triggers a console alert, a log entry, a database insert, and optionally an email notification.

---

## Features

- **Snort-style rule parsing** — supports `protocol`, `src/dst IP`, `src/dst port`, `direction` (`->`, `<-`, `<>`), and rule options (`msg`, `content`, `flow`, `threshold`, `sid`)
- **Hex and ASCII content matching** — matches raw hex bytes (`|DE AD BE EF|`) or plain strings (case-insensitive)
- **TCP flow direction detection** — distinguishes `to_server` vs `to_client` using SYN/ACK flags
- **Rate-based threshold detection** — tracks per-source or per-destination packet counts within a sliding time window
- **Structured console output** — fixed-width columns for timestamp, protocol, IPs, and ports
- **Persistent alert logging** — appends all matches to `alert.log`
- **SQLite packet database** — stores every matched packet in `packets.db`
- **Email alerting** — sends SMTP alerts via Gmail when a rule fires
- **Protocol and packet-count filters** — narrow capture scope with `-p` and `-n`
- **Verbose mode** — print full packet layer details with `-v`
- **Save to PCAP** — write a live capture session to file with `-s`

---

## Project Structure

```
Packet-Capture/
├── whole_code.py             # Main IDS — capture, rule matching, alerting, logging
├── live.py                   # Standalone live capture prototype (no rule matching)
├── snort_rules.conf          # Detection rules in Snort syntax
├── docs/
│   ├── code_breakdown.md     # Function-by-function source code documentation
│   ├── architecture.md       # System architecture and data flow
│   └── snort_rules_guide.md  # How to write and extend detection rules
├── LICENSE
└── README.md
```

---

## Requirements

| Dependency | Purpose |
|-----------|---------|
| Python 3.x | Runtime |
| [PyShark](https://github.com/KimiNewt/pyshark) | Packet capture wrapper around TShark |
| TShark | Underlying capture engine (Wireshark CLI) |
| psutil | System/process utilities |
| sqlite3 | Built-in Python — packet database |
| smtplib | Built-in Python — email alerting |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Jemskc/Packet-Capture.git
cd Packet-Capture

# 2. Install Python dependencies
pip install pyshark psutil

# 3. Install TShark (required by PyShark)
# Ubuntu / Debian
sudo apt-get install tshark

# macOS
brew install wireshark
```

> **Note:** Live packet capture requires root or administrator privileges.

---

## Usage

```bash
# Live capture on a network interface
sudo python whole_code.py -i eth0

# Analyze an existing PCAP file
python whole_code.py -o capture.pcap

# Capture only TCP packets, limit to 100, save to file
sudo python whole_code.py -i eth0 -p tcp -n 100 -s output.pcap

# Verbose mode (prints all packet layers)
sudo python whole_code.py -i eth0 -v
```

### CLI Flags

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-i` | `--interface` | Network interface for live capture (e.g. `eth0`, `wlan0`) |
| `-o` | `--open` | Path to a `.pcap` or `.pcapng` file to analyze |
| `-p` | `--protocol` | Filter by protocol (e.g. `tcp`, `http`, `dns`) |
| `-n` | `--number_of_packets` | Stop after N packets |
| `-s` | `--save_file` | Save live capture output to a PCAP file |
| `-v` | `--verbose` | Print full packet layer details |

---

## Snort Rules

Rules live in `snort_rules.conf`. Each rule follows Snort syntax:

```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

**Example rules:**

```
# Alert on any TCP packet containing "get" in the payload
alert tcp any any -> any any (msg:"Matched content tcp"; content:"get")

# Alert on HTTP traffic to/from example.com
alert http any any -> any any (msg:"Rule matched http"; content:"example.com")

# Rate-based: alert if same source sends 3+ HTTP "get" requests within 30 seconds
alert http any any -> any any (msg:"Threshold Test Rule"; sid:1000001; content:"get"; threshold:type limit, track by_src, count 3, seconds 30;)
```

See [docs/snort_rules_guide.md](docs/snort_rules_guide.md) for the full rule syntax reference.

---

## Output & Alerts

### Console

```
Time                                Protocol        Source IP            Src Port  Destination IP       Dst Port
------------------------------------------------------------------------------------------------------------------------------
Mon Jan  1 12:00:01 2024            tcp             192.168.1.5          54321     93.184.216.34        80

Alert: Matched content tcp
```

### `alert.log`

```
Matched content tcp
Time: Mon Jan  1 12:00:01 2024, Protocol: tcp, Src: 192.168.1.5:54321, Dst: 93.184.216.34:80
```

### `packets.db`

SQLite database with a `packets` table:

| Column | Type | Description |
|--------|------|-------------|
| `time` | TEXT | Timestamp of matched packet |
| `protocol` | TEXT | Highest-layer protocol |
| `src_addr` | TEXT | Source IP address |
| `dst_addr` | TEXT | Destination IP address |
| `src_port` | INTEGER | Source port |
| `dst_port` | INTEGER | Destination port |

---

## Email Configuration

To enable email alerts, edit the `send_alert_email` function in `whole_code.py`:

```python
email_address = 'your_email@gmail.com'
email_password = 'your_app_password'   # Use a Gmail App Password, not your account password
smtp_server = 'smtp.gmail.com'
smtp_port = 587
```

> **Gmail App Password:** Go to Google Account → Security → 2-Step Verification → App Passwords. Generate one for "Mail".

---

## Documentation

Detailed technical documentation is in the [`docs/`](docs/) folder:

| Document | Description |
|----------|-------------|
| [code_breakdown.md](docs/code_breakdown.md) | Every function documented with parameters, return values, and behavior |
| [architecture.md](docs/architecture.md) | System architecture, data flow, and component diagram |
| [snort_rules_guide.md](docs/snort_rules_guide.md) | Full Snort rule syntax reference and examples |

---

## Disclaimer

This tool is intended for **educational and authorized security research purposes only**. Capturing network traffic without explicit permission from the network owner is illegal in most jurisdictions. The authors assume no responsibility for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
