# Code Breakdown — `whole_code.py`

This document provides a detailed function-by-function breakdown of the main IDS implementation.

---

## Table of Contents

1. [Module Imports](#1-module-imports)
2. [Database Initialization](#2-database-initialization)
3. [`parse_options(options_str)`](#3-parse_optionsoptions_str)
4. [`parse_snort_rules(filename)`](#4-parse_snort_rulesfilename)
5. [`match_protocol`](#5-match_protocol)
6. [`match_direction`](#6-match_direction)
7. [`match_address`](#7-match_address)
8. [`match_port`](#8-match_port)
9. [`match_content`](#9-match_content)
10. [`check_threshold`](#10-check_threshold)
11. [`match_packet_to_rule`](#11-match_packet_to_rule)
12. [`send_alert_email`](#12-send_alert_email)
13. [`run_alert`](#13-run_alert)
14. [`live_capture`](#14-live_capture)
15. [`main`](#15-main)
16. [Entry Point](#16-entry-point)

---

## 1. Module Imports

```python
import os, sys, json, re
import pyshark
import smtplib
from email.mime.text import MIMEText
import time, argparse
from datetime import datetime, timedelta
import psutil
import sqlite3
```

| Module | Used For |
|--------|----------|
| `pyshark` | Wraps TShark to capture and parse network packets |
| `smtplib` / `MIMEText` | Sending email alerts over SMTP |
| `sqlite3` | Persistent storage of matched packet metadata |
| `argparse` | Parsing CLI flags (`-i`, `-o`, `-p`, etc.) |
| `datetime` / `timedelta` | Threshold time-window calculations |
| `time` | Human-readable timestamps via `time.asctime` |
| `os` / `sys` | File extension checks and clean process exits |
| `psutil`, `json`, `re` | Imported but currently unused |

---

## 2. Database Initialization

```python
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
    time TEXT, protocol TEXT, src_addr TEXT,
    dst_addr TEXT, src_port INTEGER, dst_port INTEGER)''')
```

Runs at **module load time** — creates (or opens) `packets.db` and ensures the `packets` table exists. The connection `conn` stays open for the lifetime of the process and is closed after `main()` returns.

---

## 3. `parse_options(options_str)`

**Purpose:** Parse the `(...)` options block of a single Snort rule into a structured list.

**Parameters:**
- `options_str` — the raw substring of a rule from `(` to `)`, e.g. `(msg:"Alert"; content:"GET"; sid:1;)`

**Returns:**
- `parsed_options` — list of `{key: value}` dicts for every `key:value` pair found
- `available_options` — dict of `{key: True}` for every unique key present

**How it works:**

```
"(msg:"Alert"; content:"GET"; sid:1;)"
        ↓ strip outer parens, split on ";"
["msg:\"Alert\"", "content:\"GET\"", "sid:1", ""]
        ↓ split each on first ":"
[{"msg": '"Alert"'}, {"content": '"GET"'}, {"sid": "1"}]
```

**Example:**
```python
opts, avail = parse_options('(msg:"Test"; content:"evil"; sid:42;)')
# opts  → [{"msg": '"Test"'}, {"content": '"evil"'}, {"sid": "42"}]
# avail → {"msg": True, "content": True, "sid": True}
```

---

## 4. `parse_snort_rules(filename)`

**Purpose:** Load and parse all rules from a Snort rules file into a list of structured dicts.

**Parameters:**
- `filename` — path to the rules file (e.g. `snort_rules.conf`)

**Returns:** List of rule dicts, each with these keys:

| Key | Example Value |
|-----|--------------|
| `Alert` | `"alert"` |
| `Protocol` | `"tcp"` |
| `Source Address` | `"192.168.1.0"` or `"any"` |
| `Source Port` | `"80"` or `"any"` |
| `Direction` | `"->"` |
| `Destination Address` | `"any"` |
| `Destination Port` | `"any"` |
| `Options` | `[{"msg": '"Test"'}, {"content": '"GET"'}]` |
| `Available Options` | `["msg", "content"]` |
| `Available Option Values` | `{"msg": '"Test"', "content": '"GET"'}` |

**How it works:**
1. Reads the file line by line
2. Splits each line on whitespace — first 7 tokens are the rule header fields
3. Everything from token 7 onward is joined and passed to `parse_options`
4. Builds `Available Options` (list of present keys) and `Available Option Values` (merged values per key)

---

## 5. `match_protocol`

```python
def match_protocol(packet_protocol, rule_protocol)
```

**Purpose:** Check whether a packet's protocol matches a rule's protocol field.

**Returns:** `True` if protocols match (case-insensitive) or rule is `"any"`, else `False`.

```python
match_protocol("tcp", "any")  # → True
match_protocol("tcp", "TCP")  # → True
match_protocol("udp", "tcp")  # → False
```

---

## 6. `match_direction`

```python
def match_direction(packet_src, packet_dst, rule_src, rule_dst, rule_direction)
```

**Purpose:** Validate that the packet's source/destination relationship matches the rule's directional constraint.

**Direction semantics:**

| Direction | Meaning |
|-----------|---------|
| `->` | Unidirectional: packet must flow src → dst |
| `<-` | Unidirectional: packet must flow dst → src (reversed) |
| `<>` | Bidirectional: either direction matches |
| `any` | Always matches regardless of direction |

An address in a direction slot matches if the packet address equals the rule address, or the rule address is `"any"`.

---

## 7. `match_address`

```python
def match_address(packet_address, rule_address)
```

**Purpose:** Check if a single IP address matches a rule address field.

**Returns:** `True` if equal or rule is `"any"`.

> Does not support CIDR notation (e.g. `192.168.0.0/24`) — exact IP or `any` only.

---

## 8. `match_port`

```python
def match_port(packet_port, rule_port)
```

**Purpose:** Check if a packet's port matches the rule's port field.

**Returns:** `True` if equal or rule is `"any"`.

> Does not support port ranges (e.g. `1024:65535`) — exact port or `any` only.

---

## 9. `match_content`

```python
def match_content(rule, packet_payload)
```

**Purpose:** Check whether all `content:` options in a rule match the packet's payload bytes.

**Parameters:**
- `rule` — parsed rule dict
- `packet_payload` — `bytes` object of the transport-layer payload, or `None`

**Returns:** `True` if every content option matches; `False` if any one fails or payload is `None`.

**Content types supported:**

| Format | Example | Behavior |
|--------|---------|----------|
| Quoted string | `content:"GET"` | Case-insensitive substring search in decoded payload |
| Hex bytes | `content:"\|47 45 54\|"` | Exact byte-sequence search in raw payload bytes |

**Logic:**
```
For each content: option in the rule:
    Strip surrounding quotes
    If wrapped in |...|:
        Parse as hex → search raw bytes
    Else:
        Decode payload as UTF-8 (errors ignored) → case-insensitive substring match
    If not found → return False
Return True  (all matched)
```

---

## 10. `check_threshold`

```python
def check_threshold(rule, packet, packet_counts)
```

**Purpose:** Rate-based detection — alert only when a source/destination exceeds a packet count within a rolling time window.

**Parameters:**
- `rule` — parsed rule dict
- `packet` — current PyShark packet object
- `packet_counts` — shared `dict` mapping IP → list of `datetime` timestamps (mutated in place)

**Returns:** `True` if the threshold has been reached, else `False`.

**Threshold option format:**
```
threshold: type limit, track by_src, count 3, seconds 30
```

| Field | Description |
|-------|-------------|
| `type` | `limit` or `both` — when to fire the alert |
| `track` | `by_src` (group by source IP) or `by_dst` (group by destination IP) |
| `count` | Number of packets within the window to trigger on |
| `seconds` | Rolling time window width in seconds |

**Logic:**
1. Extract `count` and `seconds` from the threshold option string
2. Append `datetime.now()` to `packet_counts[ip]`
3. Count timestamps in the list that fall within the last `seconds` seconds
4. If that count ≥ `count` → return `True`

---

## 11. `match_packet_to_rule`

```python
def match_packet_to_rule(packet, rule)
```

**Purpose:** Check the `flow:` option — filter by TCP connection state.

**Returns:** `True` if the flow condition is met, else `False`.

**Flow semantics using TCP flags:**

| Flow Keyword | SYN flag | ACK flag | Meaning |
|-------------|----------|----------|---------|
| `to_server` | `0` | `1` | Established data going to server |
| `to_client` | `1` | `1` | SYN-ACK during handshake |

Returns `False` immediately if the packet has no TCP layer.

---

## 12. `send_alert_email`

```python
def send_alert_email(rule, matched_values)
```

**Purpose:** Send an email notification when a rule fires.

**Parameters:**
- `rule` — the matched rule dict (included in email body for context)
- `matched_values` — list of strings containing the matched `content:` values

**Behavior:**
1. Builds a `MIMEText` email with rule details and matched content
2. Connects to `smtp.gmail.com:587` with STARTTLS
3. Authenticates and sends to the configured recipient address

> **Security note:** Credentials are placeholder values. Replace with a real address and a [Gmail App Password](https://support.google.com/accounts/answer/185833). Never commit real credentials to source control — use environment variables instead.

---

## 13. `run_alert`

```python
def run_alert(msg, localtime, packet_protocol, packet_src, packet_dst, packet_sport, packet_dport)
```

**Purpose:** Append a formatted alert entry to `alert.log`.

**Output format:**
```
Matched content tcp
Time: Mon Jan  1 12:00:01 2024, Protocol: tcp, Src: 192.168.1.5:54321, Dst: 93.184.216.34:80
```

---

## 14. `live_capture`

```python
def live_capture(packet_handler=None)
```

**Purpose:** Handle CLI argument parsing, open the packet source, and feed each packet to the handler callback.

**Parameters:**
- `packet_handler` — callable that accepts a single PyShark packet

**CLI Arguments parsed internally:**

| Flag | Type | Description |
|------|------|-------------|
| `-i` | str | Network interface name |
| `-o` | str | PCAP/PCAPNG file path |
| `-s` | str | Output file for live capture |
| `-n` | int | Maximum packets to capture |
| `-p` | str | Protocol filter |
| `-v` | flag | Verbose output |

**Validation:**
- Exits if neither `-i` nor `-o` is provided
- Validates `.pcap` / `.pcapng` extension for `-o`
- Catches `UnknownInterfaceException` for invalid interface names

**Packet iteration:**
- File mode: iterates `pyshark.FileCapture` directly
- Live mode: iterates `capture.sniff_continuously(packet_count=n)`
- Applies protocol filter by comparing `packet.highest_layer` to the `-p` argument

---

## 15. `main`

**Purpose:** Top-level orchestration — loads rules, defines the packet handler, and starts capture.

**Flow:**

```
1. Parse snort_rules.conf  →  list of rule dicts
2. Initialize packet_counts = {}  (shared state for threshold tracking)
3. Define packet_handler(packet) closure:
   a. Get timestamp, protocol, src/dst IP, src/dst port
   b. Extract TCP or UDP payload → convert hex string to bytes
   c. Print formatted packet summary line to console
   d. For each rule:
        Check: protocol  →  direction  →  src address  →  dst address  →  src port  →  dst port
        If header matches, check optional conditions:
          - content  →  match_content()
          - threshold  →  check_threshold()
          - flow  →  match_packet_to_rule()
        If all conditions pass:
          - Print alert to console
          - send_alert_email()
          - run_alert()  →  write to alert.log
          - INSERT row into packets.db
4. Call live_capture(packet_handler=packet_handler)
```

**Payload extraction:**
```python
# Get hex-string payload from TCP or UDP layer
payload = packet.tcp.get('tcp.payload')   # e.g. "47:45:54"
# Strip colons and decode to raw bytes
payload = bytes.fromhex(payload.replace(":", ""))  # → b"GET"
```

---

## 16. Entry Point

```python
if __name__ == "__main__":
    main()

conn.close()
```

`conn.close()` is at module scope outside the `if __name__` block. This works correctly when run as a script (connection opened at import, closed after `main()` exits) but would leave the DB connection open if this module were ever imported by another script.

---

## `live.py` — Prototype Script

`live.py` is an earlier standalone prototype. It implements basic live capture with CLI flags but **does not include rule matching, alerting, or database logging**. It is kept for reference only.

Use `whole_code.py` for all real usage.
