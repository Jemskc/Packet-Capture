# Snort Rules Guide

This guide explains the Snort-style rule syntax supported by this IDS and how to write your own detection rules.

---

## Rule Structure

Every rule follows this format:

```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

**Example:**
```
alert tcp any any -> 192.168.1.10 80 (msg:"Possible HTTP Attack"; content:"GET /admin"; sid:1000001;)
```

---

## Fields

### `action`

What to do when the rule matches. Currently only `alert` is supported.

| Value | Behavior |
|-------|----------|
| `alert` | Generate an alert (console, log, DB, email) |

---

### `protocol`

The network/transport protocol to match against.

| Value | Matches |
|-------|---------|
| `tcp` | TCP packets |
| `udp` | UDP packets |
| `http` | HTTP (application layer) |
| `any` | All protocols |

The match is case-insensitive. The engine compares against PyShark's `packet.highest_layer`.

---

### `src_ip` / `dst_ip`

The source or destination IP address to match.

| Value | Meaning |
|-------|---------|
| `any` | Match any IP address |
| `192.168.1.10` | Match this exact IP |

> CIDR notation (e.g. `192.168.0.0/24`) is **not** currently supported.

---

### `src_port` / `dst_port`

The source or destination port to match.

| Value | Meaning |
|-------|---------|
| `any` | Match any port |
| `80` | Match exactly port 80 |

> Port ranges (e.g. `1024:65535`) are **not** currently supported.

---

### `direction`

Controls which traffic direction triggers the rule.

| Value | Meaning |
|-------|---------|
| `->` | Source to destination only |
| `<-` | Destination to source only (reversed) |
| `<>` | Either direction (bidirectional) |
| `any` | Always matches |

**Example:**
```
# Only match traffic going TO port 80
alert tcp any any -> any 80 (msg:"Outbound HTTP";)

# Match traffic in either direction on port 22
alert tcp any 22 <> any 22 (msg:"SSH Traffic";)
```

---

## Options Block

Options go inside `(...)` at the end of the rule. Each option is separated by a semicolon `;`.

```
(option1:value1; option2:value2; option3;)
```

---

### `msg`

A human-readable description of the alert. Printed to the console and written to `alert.log`.

```
msg:"Suspicious outbound connection";
```

---

### `content`

Match a string or byte sequence in the packet payload.

**String match (case-insensitive):**
```
content:"GET /admin";
content:"password";
```

**Hex byte match** (wrap hex pairs in `|...|`):
```
content:"|90 90 90 90|";   # NOP sled
content:"|DE AD BE EF|";
```

Multiple `content:` options in one rule must **all** match for the rule to fire (AND logic).

---

### `threshold`

Rate-based detection — only alert after a source or destination exceeds a packet count within a time window.

**Format:**
```
threshold: type <type>, track <track>, count <n>, seconds <s>;
```

| Parameter | Options | Description |
|-----------|---------|-------------|
| `type` | `limit`, `both` | When to fire the alert |
| `track` | `by_src`, `by_dst` | Group packet counts by source or destination IP |
| `count` | integer | Packet count threshold |
| `seconds` | integer | Rolling time window in seconds |

**Example — alert if same source sends 5+ SYN packets in 10 seconds:**
```
alert tcp any any -> any 80 (msg:"Possible SYN flood"; threshold:type limit, track by_src, count 5, seconds 10;)
```

---

### `flow`

Match based on TCP connection state.

| Value | Meaning |
|-------|---------|
| `to_server` | Established session data flowing to server (ACK=1, SYN=0) |
| `to_client` | SYN-ACK response from server (SYN=1, ACK=1) |

**Example:**
```
alert tcp any any -> any 80 (msg:"HTTP request to server"; flow:to_server; content:"GET";)
```

---

### `sid`

A unique rule identifier (Snort Rule ID). Used for referencing rules in logs and management systems.

```
sid:1000001;
```

SIDs 1–999,999 are reserved for official Snort rules. Use `1000001` and above for custom rules.

---

## Complete Examples

```
# 1. Alert on any TCP packet with "GET" in the payload
alert tcp any any -> any any (msg:"TCP GET request detected"; content:"GET"; sid:1000001;)

# 2. Alert on HTTP traffic to/from example.com
alert http any any -> any any (msg:"Traffic to example.com"; content:"example.com"; sid:1000002;)

# 3. Rate-based: alert if a single source sends 3+ HTTP GETs in 30 seconds
alert http any any -> any any (msg:"HTTP request flood"; content:"GET"; threshold:type limit, track by_src, count 3, seconds 30; sid:1000003;)

# 4. Alert on NOP sled in TCP payload (shellcode indicator)
alert tcp any any -> any any (msg:"Possible NOP sled"; content:"|90 90 90 90|"; sid:1000004;)

# 5. Bidirectional alert on SSH port
alert tcp any 22 <> any 22 (msg:"SSH traffic observed"; sid:1000005;)

# 6. Alert on established HTTP flows going to port 80
alert tcp any any -> any 80 (msg:"Established HTTP session data"; flow:to_server; content:"POST"; sid:1000006;)
```

---

## Rules File Format

- One rule per line in `snort_rules.conf`
- Blank lines and comments (lines starting with `#`) are not currently handled — keep only valid rule lines
- Rules are evaluated in order from top to bottom; all matching rules fire

---

## Limitations

The following Snort features are parsed but not fully implemented:

| Feature | Status |
|---------|--------|
| CIDR IP ranges | Not supported — exact IP or `any` only |
| Port ranges (`1024:65535`) | Not supported — exact port or `any` only |
| Negation (`!192.168.1.1`) | Not supported |
| `pcre:` option | Not supported |
| `noalert` / `pass` / `drop` actions | Not supported — only `alert` |
| `classtype:` / `priority:` | Parsed but not used |
