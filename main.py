#!/usr/bin/env python3
import time

from ids.rules    import parse_snort_rules
from ids.matcher  import header_matches, evaluate_rule
from ids.alerter  import run_alert, send_alert_email
from ids.database import PacketDatabase
from ids.capture  import run_capture

RULES_FILE = 'snort_rules.conf'


def extract_packet_fields(packet):
    """Pull protocol, IPs, ports, and payload out of a PyShark packet."""
    localtime = time.asctime(time.localtime(time.time()))
    protocol  = packet.highest_layer.lower().replace('_raw', '')

    if 'IP' in packet:
        src = packet['IP'].src
        dst = packet['IP'].dst
    else:
        src = dst = 'N/A'

    sport = dport = ''
    for layer in packet.layers:
        if hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
            sport = layer.srcport
            dport = layer.dstport
            break

    payload = None
    if hasattr(packet, 'tcp'):
        payload = packet.tcp.get('tcp.payload')
    elif hasattr(packet, 'udp'):
        payload = packet.udp.get('udp.payload')

    if payload is not None:
        try:
            payload = bytes.fromhex(payload.replace(':', ''))
        except ValueError:
            payload = None

    return localtime, protocol, src, dst, sport, dport, payload


def main():
    parsed_rules  = parse_snort_rules(RULES_FILE)
    packet_counts = {}
    db = PacketDatabase()

    header_fmt = '{:<35} {:<15} {:<20} {:<15} {:<20} {:<15}'

    def packet_handler(packet):
        localtime, protocol, src, dst, sport, dport, payload = extract_packet_fields(packet)

        print(header_fmt.format(localtime, protocol, src, sport, dst, dport))
        db.log(localtime, protocol, src, dst, sport, dport)

        for rule in parsed_rules:
            if not header_matches(protocol, src, dst, sport, dport, rule):
                continue
            if not evaluate_rule(rule, packet, payload, packet_counts):
                continue

            matched_values = [
                opt['content'].strip('"')
                for opt in rule['Options']
                if 'content' in opt
            ]
            for opt in rule['Options']:
                if 'msg' in opt:
                    print(f"\nAlert: {opt['msg']}\n")
                    run_alert(opt['msg'], localtime, protocol, src, dst, sport, dport)
                    send_alert_email(rule, matched_values)

    try:
        run_capture(packet_handler)
    finally:
        db.close()


if __name__ == '__main__':
    main()
