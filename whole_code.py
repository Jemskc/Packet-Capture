#!/usr/bin/python
import os
import sys
import json
import re
import pyshark
import smtplib
from email.mime.text import MIMEText
import time
import argparse
from datetime import datetime, timedelta
import psutil
import sqlite3

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
    for option in rule['Options']:
        if 'flow' in option.keys():
            if hasattr(packet, 'tcp'):  # Add this condition
                if 'to_server' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                elif 'to_client' in option['flow'] and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                    return True
            else:
                return False
    return False


def send_alert_email(rule, matched_values):
    email_address = 'abc@gmail.com'
    email_password = 'your_password'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    
    if 'Options' not in rule:
        print("Rule doesn't contain 'Options' key")
        return
    
    content_str = ", ".join(matched_values)
    msg = MIMEText(f"Packet content matched for rule: {rule['Options']}\nMatched content: {content_str}")
    msg['Subject'] = f"Alert: Packet content matched for rule {rule['Options']}"
    msg['From'] = "abc@gmail.com"
    msg['To'] = "123@gmail.com"
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_address, email_password)
        server.sendmail(email_address, msg['To'], msg.as_string())
        server.quit()
#        print(f"Email alert sent to {msg['To']}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")


conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

# Create a table for the packets if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
                time TEXT, protocol TEXT, src_addr TEXT, dst_addr TEXT, src_port INTEGER, dst_port INTEGER)''')


def run_alert(msg, localtime, packet_protocol, packet_src, packet_dst, packet_sport, packet_dport):
    alert_msg = f"{msg}\nTime: {localtime}, Protocol: {packet_protocol}, Src: {packet_src}:{packet_sport}, Dst: {packet_dst}:{packet_dport}\n"
    with open('alert.log', 'a') as f:
        f.write(alert_msg + '\n')


def live_capture(packet_handler=None):
    parser = argparse.ArgumentParser(description="""This is the Packet capture and analysis capture packet wiht APT group. This tool has two feature one is to capture the packet and analyze the packet wiht the rules file for malicious packet detection.
      
    You have to specify either -i option for captureing live packet of -o option for opening the cpature pcap file. Do not use both at once.
      
    For example: python <script.name> -i interface_name (to live capture packet)
     or python <script.name> -o <file.pcap> (to open pcap file)""", formatter_class=argparse.RawTextHelpFormatter )
 
    parser.add_argument('-i', '--interface',metavar='', help='To specify the interface that is runnning in your OS for live packet capturing.')
    parser.add_argument('-o', '--open', metavar='', help='To open the pcap file')
    parser.add_argument('-s', '--save_file', metavar='',help='To save the livecapture packet in a file.')
    parser.add_argument('-n', '--number_of_packets', metavar='', type=int, help='To capture the limited number of packets to capture.')
    parser.add_argument('-p', '--protocol', metavar='', help='To specify one protocol and capture packet of that protocol only.')
    parser.add_argument('-v', '--verbose', action='store_true', help='To capture the packet with all the layer inforamtion.')

    args = parser.parse_args()

    if not args.interface and not args.open:
        print("Error: You must provide either -i (--interface) or -o (--open) option.")
        parser.print_help()
        sys.exit(1)
    if args.open:
        extension_of_file = os.path.splitext(args.open)[1]
        if extension_of_file.lower() not in ['.pcapng', ".pcap"]:
           print("Error: The file must have .pcap of .pcapng")
           sys.exit(1)
        try:
           capture = pyshark.FileCapture(args.open)
        except FileNotFoundError as e:
           print("Error: The file doesnot exit. Please check the file path.")
           sys.exit(1)
    else:
        try:
           capture = pyshark.LiveCapture(interface=args.interface, output_file=args.save_file)
        except pyshark.capture.live_capture.UnknownInterfaceException as e:
           print(f"Error: The provided interface '{args.interface}' does not exist or could not be accessed. Please check the interface name or your permissions.")
           sys.exit(1)

    header_format = "{:<35} {:<15} {:<20} {:<15} {:<20} {:<15}"
    print(header_format.format("Time", "Protocol", "Source IP", "Src Port", "Destination IP", "Dst Port"))
    print("------------------------------------------------------------------------------------------------------------------------------     ")

    if args.open:
        for i, packet in enumerate(capture):
            if args.number_of_packets and i >= args.number_of_packets:
                break

            if not args.protocol or packet.highest_layer.lower() == args.protocol.lower():
                if packet_handler(packet):
                    packet_handler(packet)
                if args.verbose:
                    print(packet)

    else:
        for i, packet in enumerate(capture.sniff_continuously(packet_count=args.number_of_packets)):
            if args.number_of_packets and i >= args.number_of_packets:
                break

            if not args.protocol or packet.highest_layer.lower() == args.protocol.lower():
                if packet_handler(packet):
                    packet_handler(packet)
                if args.verbose:
                    print(packet)





def main():

    parsed_rules = parse_snort_rules('snort_rules.conf')
    packet_counts= {}
    def packet_handler(packet):
        localtime = time.asctime(time.localtime(time.time()))
        packet_protocol = packet.highest_layer.lower().replace('_raw', '')
        packet_sport = None or ''
        packet_dport = None or ''
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
#                print(f"Invalid payload: {payload}")
                payload = None
    # Print the payload in normal form
        header_format = "{:<35} {:<15} {:<20} {:<15} {:<20} {:<15}"
        print(header_format.format(localtime, packet_protocol, packet_src, packet_sport, packet_dst, packet_dport ))
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
                            print("")
                            print("Alert: ",option['msg'])
                            print("")
                            send_alert_email(rule, matched_values)
                            run_alert(option['msg'], localtime, packet_protocol, packet_src, packet_dst, packet_sport, packet_dport)

        cursor.execute("INSERT INTO packets VALUES (?,?,?,?,?,?)", (localtime,packet_protocol,packet_src,packet_dst,packet_sport,packet_dport))
        conn.commit()

    live_capture(packet_handler=packet_handler)

if __name__ == "__main__":
    main()


conn.close()      
