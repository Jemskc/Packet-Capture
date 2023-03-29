 #!/usr/bin/python
import sys
import json
import re
import pyshark
import smtplib
from email.mime.text import MIMEText
import time
import argparse

def parse_options(options_str):
    options = options_str[options_str.index('(') + 1:options_str.rindex(')')].split(';')
    parsed_options = []
    for option in options:
        if ':' in option:
            k, v = option.strip().split(':', 1)
            parsed_options.append({k.strip(): v.strip()})
    available_options = {}
    for option in parsed_options:
        for key in option.keys():
            available_options[key] = True
    return parsed_options, available_options

def parse_snort_rules(filename):
    with open(filename, 'r') as f:
        rules = f.read().splitlines()
    parsed_rules = []
    for rule in rules:
        rule_parts = rule.strip().split()
        rule = {
            'Alert': rule_parts[0],
            'Protocol': rule_parts[1],
            'Source Address': rule_parts[2],
            'Source Port': rule_parts[3],
            'Direction': rule_parts[4],
            'Destination Address': rule_parts[5],
            'Destination Port': rule_parts[6],
            'Options': []
        }
        if len(rule_parts) > 7:
            options_str = ' '.join(rule_parts[7:])
            rule['Options'], available_options = parse_options(options_str)
        rule_options = {}
        for key in available_options.keys():
            rule_options[key] = False
        for option in rule['Options']:
            for key in option.keys():
                if key in rule_options:
                    rule_options[key] = True
        rule['Available Options'] = [key for key, value in rule_options.items() if value]
        rule['Available Option Values'] = {}
        for key in rule_options.keys():
            if key in available_options.keys():
                rule['Available Option Values'][key] = ''
        for option in rule['Options']:
            for key in option.keys():
                if key in rule['Available Option Values']:
                    rule['Available Option Values'][key] += option[key]
        parsed_rules.append(rule)
    return parsed_rules


def match_protocol(packet_protocol, rule_protocol):
    if rule_protocol == "any":
        return True
    else:
        return packet_protocol.upper() == rule_protocol.upper()

def match_direction(packet_src, packet_dst, rule_src, rule_dst, rule_direction):
    if rule_direction == "any":
        return True
    else:
        if rule_direction == "->":
            return (packet_src == rule_src or rule_src == "any") and (packet_dst == rule_dst or rule_dst == "any")
        elif rule_direction == "<-":
            return (packet_src == rule_dst or rule_dst == "any") and (packet_dst == rule_src or rule_src == "any")
        elif rule_direction == "<>":
            return ((packet_src == rule_src or rule_src == "any") and (packet_dst == rule_dst or rule_dst == "any")) or ((packet_src == rule_dst or rule_dst == "any") and (packet_dst == rule_src or rule_src == "any"))
        else:
            return False

def match_address(packet_address, rule_address):
    if rule_address == "any":
        return True
    else:
        return packet_address == rule_address

def match_port(packet_port, rule_port):
    if rule_port == "any":
        return True
    else:
        return packet_port == rule_port



def match_content(rule, packet_payload):
    content_options = [option for option in rule['Options'] if 'content' in option]

    for option in content_options:
        value = option['content']
        value = value.strip('"')

        if value.startswith('|') and value.endswith('|'):
            value = bytes.fromhex(value[1:-1].replace(' ', ''))
            if packet_payload is None or value not in packet_payload:
                return False
        else:
            if packet_payload is None or value.lower() not in packet_payload.decode('utf-8', errors='ignore').lower():
                return False

    return True



def check_threshold(rule, packet, packet_counts):
    if 'threshold' in rule['Available Options']:
        threshold_options = [option for option in rule['Options'] if 'threshold' in option]
        for option in threshold_options:
            threshold_value = option['threshold']
            threshold_type, threshold_track, threshold_count, threshold_seconds = map(str.strip, threshold_value.split(','))

            if 'both' in threshold_type.lower() or 'limit' in threshold_type.lower():
                count = int(threshold_count.split()[1])
                seconds = int(threshold_seconds.split()[1])

                if 'by_src' in threshold_track.lower():
                    src_ip = packet.ip.src

                    if src_ip not in packet_counts:
                        packet_counts[src_ip] = []

                    packet_counts[src_ip].append(datetime.now())

                    for ip, timestamps in packet_counts.items():
                        num_packets = sum((datetime.now() - t) <= timedelta(seconds=seconds) for t in timestamps)
                        if num_packets >= count:
                            return True

                elif 'by_dst' in threshold_track.lower():
                    dst_ip = packet.ip.dst

                    if dst_ip not in packet_counts:
                        packet_counts[dst_ip] = []

                    packet_counts[dst_ip].append(datetime.now())

                    for ip, timestamps in packet_counts.items():
                        num_packets = sum((datetime.now() - t) <= timedelta(seconds=seconds) for t in timestamps)
                        if num_packets >= count:
                            return True

    return False


def match_packet_to_rule(packet, rule):
    ...
    for option in rule['Options']:
        if 'flow' in option.keys():
            if hasattr(packet, 'tcp'):  # Add this condition
                if 'to_server' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    ...
                elif 'to_client' in option['flow'] and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                    ...
            else:
                return False
    ...



def send_alert_email(rule, matched_values):
    email_address = 'kcj94355@gmail.com'
    email_password = 'ykfirsbcglfreqls'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    
    if 'Options' not in rule:
        print("Rule doesn't contain 'Options' key")
        return
    
    content_str = ", ".join(matched_values)
    msg = MIMEText(f"Packet content matched for rule: {rule['Options']}\nMatched content: {content_str}")
    msg['Subject'] = f"Alert: Packet content matched for rule {rule['Options']}"
    msg['From'] = "kcj94355@gmail.com"
    msg['To'] = "np01nt4s210051@islingtoncollege.edu.np"
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_address, email_password)
        server.sendmail(email_address, msg['To'], msg.as_string())
        server.quit()
        print(f"Email alert sent to {msg['To']}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")




def live_capture(packet_handler=None):
    parser = argparse.ArgumentParser(description='Packet capture and analysis tool.')

    parser.add_argument('-i', '--interface', help='Interface to capture packets from')
    parser.add_argument('-o', '--output', help='Capture file to read packets from')
    parser.add_argument('-s', '--save-file', help='File to save live capture packets to')
    parser.add_argument('-n', '--num-packets', type=int, help='Number of packets to capture')
    parser.add_argument('-p', '--protocol', help='Protocol to filter packets by')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print packet details')

    args = parser.parse_args()

    if not args.interface and not args.output:
        print("Error: You must provide either -i (--interface) or -o (--output) option.")
        parser.print_help()
        sys.exit(1)

    if args.output:
        capture = pyshark.FileCapture(args.output)
    else:
        capture = pyshark.LiveCapture(interface=args.interface, output_file=args.save_file)

    if args.output:
        for i, packet in enumerate(capture):
            if args.num_packets and i >= args.num_packets:
                break

            if not args.protocol or packet.highest_layer.lower() == args.protocol.lower():
                if args.verbose:
                    print(packet)

                if packet_handler:
                    packet_handler(packet)
    else:
        for i, packet in enumerate(capture.sniff_continuously(packet_count=args.num_packets)):
            if args.num_packets and i >= args.num_packets:
                break

            if not args.protocol or packet.highest_layer.lower() == args.protocol.lower():
                if args.verbose:
                    print(packet)

                if packet_handler:
                    packet_handler(packet)


def main():
    parsed_rules = parse_snort_rules('snort_rules.conf')
    packet_counts= {}
    def packet_handler(packet):
        localtime = time.asctime(time.localtime(time.time()))
        packet_protocol = packet.highest_layer.lower().replace('_raw', '')
        packet_sport = None
        packet_dport = None
        if 'IP' in packet:
            packet_src = packet['IP'].src
            packet_dst = packet['IP'].dst
        else:
            packet_src = 'N/A'
            packet_dst = 'N/A'

        for layer in packet.layers:
            if hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                packet_sport = layer.srcport
                packet_dport = layer.dstport
                break
        
        
        payload = None
        if hasattr(packet, 'tcp'):
            payload = packet.tcp.get('tcp.payload')
        elif hasattr(packet, 'udp'):
            payload = packet.udp.get('udp.payload')

        if payload is not None:
        # Replace ":" in the payload
            payload = payload.replace(":", "")
        # Convert the payload to bytes
            try:
                payload = bytes.fromhex(payload)
            except ValueError:
                print(f"Invalid payload: {payload}")
                payload = None
    # Print the payload in normal form

        print(f"{localtime}\t{packet_protocol}\t{packet_src}\t{packet_sport}\t{packet_dst}\t{packet_dport}")

        for rule in parsed_rules:
            if (match_protocol(packet_protocol, rule['Protocol']) and
                match_direction(packet_src, packet_dst, rule['Source Address'], rule['Destination Address'], rule['Direction']) and
                match_address(packet_src, rule['Source Address']) and
                match_address(packet_dst, rule['Destination Address']) and
                match_port(packet_sport, rule['Source Port']) and
                match_port(packet_dport, rule['Destination Port'])):

                match = True

                if 'content' in rule['Available Options']:
                    match &= match_content(rule, payload)

                if 'threshold' in rule['Available Options']:
                    match &= check_threshold(rule, packet, packet_counts)

                if 'flow' in rule['Available Options']:
                    match &= match_packet_to_rule(packet, rule)

                if match:
                    matched_values = [option['content'].strip('"') for option in rule['Options'] if 'content' in option]
                    for option in rule['Options']:
                        if 'msg' in option.keys():
                            print(option['msg'])
               # send_alert_email(rule, matched_values)

#                send_alert_email(rule, matched_values)

    live_capture(packet_handler=packet_handler)


if __name__ == "__main__":
    main()
