 #!/usr/bin/python


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


def match_content(rule_content, packet_content):
    content_options = []
    for option in rule['Options']:
        if 'content' in option:
            content_options.append(option)

#    print('Rule:', rule['Alert'], content_options)

    content_matches = []
    for option in content_options:
        value = option['content']
        value = value.strip('"')
        if value.lower() in str(packet_content).lower():
            content_matches.append(value)

    if len(content_options) > 0 and len(content_matches) == len(content_options):
#        print('Alert: All content options match')
        return True
    elif len(content_options) > 0 and len(content_matches) < len(content_options):
 #       print('Alert: Not all content options match')
        return False
    else:
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
    # Match TCP flags with flow option in the rule
    if 'flow' in rule['Available Options']:
        for option in rule['Options']:
            if 'flow' in option:
                # Check for flow option 'to_server'
                if 'to_server' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                # Check for flow option 'to_client'
                elif 'to_client' in option['flow'] and packet.tcp.flags_push == '1' and packet.tcp.flags_ack == '1':
                    return True
                # Check for flow option 'established'
                elif 'established' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                # Check for flow option 'to_client,established'
                elif 'to_client' in option['flow'] and 'established' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                # Check for flow option 'to_server,established'
                elif 'to_server' in option['flow'] and 'established' in option['flow'] and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
    return False



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
    # Create the argument parser
    parser = argparse.ArgumentParser(description='A simple PyShark example that captures live packets from a network interface.')

    # Add the command line options
    parser.add_argument('-i', '--interface', type=str, default=None, help='Network interface to capture packets from')
    parser.add_argument('-n', '--num_packets', type=int, default=None, help='Limit number of packets to capture')
    parser.add_argument('-t', '--tcp', action='store_true', help='Show only TCP packets')
    parser.add_argument('-p', '--protocol', type=str, default=None, help='Filter packets by protocol')
    parser.add_argument('-s', '--save_file', type=str, default=None, help='Save captured packets to a pcap file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed packet information')

    # Parse the command line arguments
    args = parser.parse_args()

    # Create the live capture object
    capture = pyshark.LiveCapture(interface=args.interface, use_json=True, include_raw=True)

    # Apply the filters
    if args.tcp:
        capture.set_debug()
        capture.filter('tcp')
    if args.protocol:
        capture.set_debug()
        capture.filter(args.protocol)

    # Start capturing packets
    for i, packet in enumerate(capture.sniff_continuously(packet_count=args.num_packets)):
        if args.num_packets and i >= args.num_packets:
            break

        if args.verbose:
            print(packet)

        if packet_handler:
            packet_handler(packet)

        if args.save_file:
            with open(args.save_file, 'ab') as f:
                f.write(bytes(packet))


def main():
    parsed_rules = parse_snort_rules('snort_rules.conf')

    def packet_handler(packet):
        packet_content = packet.get_raw_packet() 
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

        print(f"{localtime}\t{packet_protocol}\t{packet_src}\t{packet_sport}\t{packet_dst}\t{packet_dport}")

        for rule in parsed_rules:
            if (match_protocol(packet_protocol, rule['Protocol']) and
                match_direction(packet_src, packet_dst, rule['Source Address'], rule['Destination Address'], rule['Direction']) and
                match_address(packet_src, rule['Source Address']) and
                match_address(packet_dst, rule['Destination Address']) and
                match_port(packet_sport, rule['Source Port']) and
                match_port(packet_dport, rule['Destination Port'])and
                match_content(rule['Available Option Values'], packet_content)):
                matched_values = [option['content'].strip('"') for option in rule['Options'] if 'content' in option]
                for option in rule['Options']:
                    if 'msg' in option.keys():
                        print(option['msg'])
                send_alert_email(rule, matched_values)

    live_capture(packet_handler=packet_handler)



def print_packets(run=False):
    if not run:
        return

    def print_pcap_packets(src=False, dst=False, num_packets=None, tcp=False, file_name=None):
        # create the argument parser
        parser = argparse.ArgumentParser(description='A simple PyShark example that prints packets from a pcap file.')

        # add the command line options
        parser.add_argument('--src', action='store_true', help='Print source IP address only')
        parser.add_argument('--dst', action='store_true', help='Print destination IP address only')
        parser.add_argument('-n', '--num_packets', type=int, default=None, help='Limit number of packets to display')
        parser.add_argument('-t', '--tcp', action='store_true', help='Show only TCP packets')
        parser.add_argument('-o', '--output', type=str, default=None, help='Name of the pcap file to open')
        parser.add_argument('-p', '--protocol', type=str, default=None, help='Filter packets by protocol')
        # parse the command line arguments
        args = parser.parse_args()
        
        try:
        # check if the user specified a file name
            if args.output:
               file_name = args.output
            else:
               raise ValueError("pcap file missing -o option")

        # open the pcap file
            cap = pyshark.FileCapture(file_name)

        # loop through each packet in the pcap file
            for i, packet in enumerate(cap):
            # exit if we have displayed the maximum number of packets
                if args.num_packets is not None and i >= args.num_packets:
                   break

            # check if we should filter by protocol
                if args.tcp and 'TCP' not in packet.highest_layer:
                   continue
                if args.protocol and args.protocol.upper() not in packet.highest_layer.upper():
                   continue
            # print the appropriate fields based on the command line options
                if args.src:
                   print(packet.ip.src)
                elif args.dst:
                   print(packet.ip.dst)
                else:
                   print(packet.ip.src, packet.ip.dst, packet.highest_layer)

        except ValueError as e:
            print("Error occurred:", e)
            exit()
        except Exception as e:
            print("Error occurred:", e)
            exit()
        # The rest of the print_pcap_packets function remains the same...

    print_pcap_packets()




if __name__ == "__main__":
    main()
