#!/usr/bin/python

import time
import pyshark
import re

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
    if 'flow' in rule['Available Options']:
        for option in rule['Options']:
            if 'flow' in option:
                if option['flow'] == 'to_server' and packet.tcp.flags_syn == '0' and packet.tcp.flags_ack == '1':
                    return True
                elif option['flow'] == 'to_client' and packet.tcp.flags_push == '1' and packet.tcp.flags_ack == '1':
                    return True
    return False

# Parse Snort rules
rules = parse_snort_rules('snort_rules.conf')

# Capture packets using PyShark
capture = pyshark.LiveCapture(interface='eth0', bpf_filter='tcp')
capture.sniff(timeout=10)

# Match packets with rules
for packet in capture:
    print(packet.tcp.flags_syn, packet.tcp.flags_push, packet.tcp.flags_ack, packet.ip.src,packet.ip.dst)
    for rule in rules:
        if match_packet_to_rule(packet, rule):
            print('Packet matched with rule:', rule)
            # Do alerting here
        else:
            print('packet not matched') 
