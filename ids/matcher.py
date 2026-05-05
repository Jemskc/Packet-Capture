from datetime import datetime, timedelta


def match_protocol(packet_protocol, rule_protocol):
    if rule_protocol == 'any':
        return True
    return packet_protocol.upper() == rule_protocol.upper()


def match_direction(packet_src, packet_dst, rule_src, rule_dst, rule_direction):
    if rule_direction == 'any':
        return True

    def addr_match(pkt, rule):
        return rule == 'any' or pkt == rule

    if rule_direction == '->':
        return addr_match(packet_src, rule_src) and addr_match(packet_dst, rule_dst)
    if rule_direction == '<-':
        return addr_match(packet_src, rule_dst) and addr_match(packet_dst, rule_src)
    if rule_direction == '<>':
        fwd = addr_match(packet_src, rule_src) and addr_match(packet_dst, rule_dst)
        rev = addr_match(packet_src, rule_dst) and addr_match(packet_dst, rule_src)
        return fwd or rev
    return False


def match_address(packet_address, rule_address):
    return rule_address == 'any' or packet_address == rule_address


def match_port(packet_port, rule_port):
    return rule_port == 'any' or packet_port == rule_port


def match_content(rule, packet_payload):
    """Return True if all content: options in the rule match the payload bytes."""
    for option in rule['Options']:
        if 'content' not in option:
            continue
        value = option['content'].strip('"')
        if value.startswith('|') and value.endswith('|'):
            needle = bytes.fromhex(value[1:-1].replace(' ', ''))
            if packet_payload is None or needle not in packet_payload:
                return False
        else:
            decoded = '' if packet_payload is None else packet_payload.decode('utf-8', errors='ignore')
            if value.lower() not in decoded.lower():
                return False
    return True


def check_threshold(rule, packet, packet_counts):
    """Return True if the packet count from a tracked IP exceeds the threshold window."""
    if 'threshold' not in rule['Available Options']:
        return False

    for option in rule['Options']:
        if 'threshold' not in option:
            continue

        parts = list(map(str.strip, option['threshold'].split(',')))
        threshold_type, threshold_track, threshold_count, threshold_seconds = parts

        if 'limit' not in threshold_type.lower() and 'both' not in threshold_type.lower():
            continue

        count = int(threshold_count.split()[1])
        seconds = int(threshold_seconds.split()[1])
        window = timedelta(seconds=seconds)

        if 'by_src' in threshold_track.lower():
            ip = packet.ip.src
        elif 'by_dst' in threshold_track.lower():
            ip = packet.ip.dst
        else:
            continue

        packet_counts.setdefault(ip, []).append(datetime.now())
        now = datetime.now()
        if sum((now - t) <= window for t in packet_counts[ip]) >= count:
            return True

    return False


def match_flow(rule, packet):
    """Return True if the packet's TCP flags match the flow: option."""
    for option in rule['Options']:
        if 'flow' not in option:
            continue
        if not hasattr(packet, 'tcp'):
            return False
        flow = option['flow']
        syn = packet.tcp.flags_syn
        ack = packet.tcp.flags_ack
        if 'to_server' in flow and syn == '0' and ack == '1':
            return True
        if 'to_client' in flow and syn == '1' and ack == '1':
            return True
    return False


def evaluate_rule(rule, packet, payload, packet_counts):
    """Run all option checks for a rule that already passed the header match.

    Returns True if every applicable option matches.
    """
    match = True
    if 'content' in rule['Available Options']:
        match = match and match_content(rule, payload)
    if 'threshold' in rule['Available Options']:
        match = match and check_threshold(rule, packet, packet_counts)
    if 'flow' in rule['Available Options']:
        match = match and match_flow(rule, packet)
    return match


def header_matches(packet_protocol, packet_src, packet_dst, packet_sport, packet_dport, rule):
    """Check protocol, direction, address, and port fields of a rule header."""
    return (
        match_protocol(packet_protocol, rule['Protocol']) and
        match_direction(packet_src, packet_dst,
                        rule['Source Address'], rule['Destination Address'],
                        rule['Direction']) and
        match_address(packet_src, rule['Source Address']) and
        match_address(packet_dst, rule['Destination Address']) and
        match_port(packet_sport, rule['Source Port']) and
        match_port(packet_dport, rule['Destination Port'])
    )
