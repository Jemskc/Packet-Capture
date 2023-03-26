 #!/usr/bin/python

import re
import pyshark
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

 
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


def match_packet_to_rule(packet, rule):
    # Match TCP flags with flow option in the rule
    if not hasattr(packet, 'tcp') or not hasattr(packet.tcp, 'flags_syn') or not hasattr(packet.tcp, 'flags_ack') or not hasattr(packet.tcp, 'flags_push'):
        return False
    if 'flow' in rule['Available Options']:
        for option in rule['Options']:
            if 'flow' in option:
                if option['flow'] == 'to_server' and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                elif option['flow'] == 'to_client' and packet.tcp.flags_push == '1' and packet.tcp.flags_ack == '1':
                    return True

    # Match content option in the rule
    # Match content option in the rule
    if 'content' in rule['Available Options']:
        content_options = [option for option in rule['Options'] if 'content' in option]
        for option in content_options:
            value = option['content'].strip('"')
            if value.lower() in str(packet).lower():
               print(f"Packet: {packet}, Option: {option}, Value: {value}")
            return True
    return False



    if 'threshold' in rule['Available Options']:
        threshold_options = [option for option in rule['Options'] if 'threshold' in option]
        for option in threshold_options:
            threshold_value = option['threshold']
            threshold_type, threshold_track, threshold_count, threshold_seconds = map(str.strip,  threshold_value.split(','))

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
                            if 'msg' in rule['Available Options']:
                                print(f"ALERT: {rule['Available Option Values']['msg']}")
                            return True

                elif 'by_dst' in threshold_track.lower():
                    dst_ip = packet.ip.dst

                    if dst_ip not in packet_counts:
                        packet_counts[dst_ip] = []

                    packet_counts[dst_ip].append(datetime.now())

                    for ip, timestamps in packet_counts.items():
                        num_packets = sum((datetime.now() - t) <= timedelta(seconds=seconds) for t in timestamps)

                        if num_packets >= count:
                            if 'msg' in rule['Available Options']:
                                print(f"ALERT: {rule['Available Option Values']['msg']}")
                            return True


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

'''

def send_alert_email(rule, matched_values):
    email_address = 'kcj94355@gmail.com'
    email_password = 'ykfirsbcglfreqls'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    
    if 'Options' not in rule:
        print("Rule doesn't contain 'Options' key")
        return
    
    content_str = ", ".join(matched_values)
    msg = MIMEText(f"Packet content matched for rule: {rule['Options']}\nMatched content: {contain_str}")

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

'''



packet_counts = {}
rules = parse_snort_rules('snort_rules.conf')
capture = pyshark.LiveCapture(interface='eth0', include_raw=True, use_json=True)
'''
for packet in cap:
    raw_packet = bytes(packet.get_raw_packet())
    packet_str = raw_packet.decode(errors='ignore')  
    print(packet.ip.src, packet.ip.dst, packet.highest_layer)
    print('')
    print(raw_packet)
    print('')
'''
for packet in capture.sniff_continuously(packet_count=20):
    # Get raw packet bytes
    raw_packet = packet.get_raw_packet()
    packet_str = raw_packet.decode(errors='ignore') 
    print('raw_packet: ', raw_packet)
    protocol = packet.highest_layer.lower().replace('_raw', '')
    packet_sport = None
    packet_dport = None
    for layer in packet.layers:
        # Check if the layer has a source and destination port
        if hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
            # Get the source and destination ports
            packet_sport = layer.srcport
            packet_dport = layer.dstport
            break

    print(protocol, packet.ip.src,packet.ip.dst,packet_sport,packet_dport)
    print('')
    for rule in rules:

       if protocol == rule['Protocol']:
           if match_address(packet.ip.src, rule['Source Address']) and match_address(packet.ip.dst, rule['Destination Address']):
        # Match source and destination port
               if match_port(packet_sport, rule['Source Port']) and match_port(packet_dport, rule['Destination Port']):

                  if match_packet_to_rule(packet, rule):
                     print("Alert packet match the rule completely")
#                     send_alert_email(rule, matched_values)

                  else:
                     print("Packet not matched")

