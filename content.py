
#!/usr/bin/python
import re
import pyshark
import smtplib
from email.mime.text import MIMEText
import time

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
'''
def content_matching(rule,packet_str):
    if 'content' in rule['Available Options']:
        value = rule['Available Option Values']['content']
    # remove inverted commas
        value = value.strip('"')
    
        if value.lower() in packet_str.lower():
           print('Alert packet matched')
        else:
           print('Value not matched...')
'''


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



parsed_rules = parse_snort_rules('snort_rules.conf')

cap = pyshark.LiveCapture(interface='eth0',use_json=True, include_raw=True)
cap.sniff(packet_count=10)



for packet in cap.sniff_continuously():
    packet_content = packet.get_raw_packet() 
    localtime = time.asctime(time.localtime(time.time()))
    packet_protocol = packet.highest_layer.lower().replace('_raw', '')
    packet_src = packet.ip.src
    packet_dst = packet.ip.dst
    for layer in packet.layers:
                # Check if the layer has a source and destination port
        if hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                    # Get the source and destination ports
           packet_sport = layer.srcport
           packet_dport = layer.dstport
           break
    print(localtime, '\t', packet_protocol, '\t', packet_src, '\t', packet_sport, '\t', packet_dst, '\t', packet_dport)

#    print(packet_content)
    for rule in parsed_rules:
        if (match_protocol(packet_protocol, rule['Protocol']) and
            match_direction(packet_src, packet_dst, rule['Source Address'], rule['Destination Address'], rule['Direction']) and
            match_address(packet_src, rule['Source Address']) and
            match_address(packet_dst, rule['Destination Address']) and
            match_port(packet_sport, rule['Source Port']) and
            match_port(packet_dport, rule['Destination Port'])and
            match_content(rule['Available Option Values'], packet_content)):
            for option in rule['Options']:
                
                if 'msg' in option.keys():
                    print(option['msg'])

