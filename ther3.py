#!/usr/bin/python

import pyshark
import re
from datetime import datetime, timedelta

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
def check_threshold(packet, rule, packet_counts):
    if 'threshold' in rule['Available Options']:
        threshold_options = [option for option in rule['Options'] if 'threshold' in option]
        for option in threshold_options:
            threshold_value = option['threshold']
            threshold_parts = threshold_value.split(";")
            if len(threshold_parts) != 4:
                continue
            threshold_type, threshold_track, threshold_count, threshold_seconds = map(str.strip, threshold_parts)

            if 'both' in threshold_type.lower() or 'limit' in threshold_type.lower():
                count = int(threshold_count.split()[1])
                seconds = int(threshold_seconds.split()[1])

                if 'by_src' in threshold_track.lower():
                    src_ip = packet.ip.src

                    if src_ip not in packet_counts:
                        packet_counts[src_ip] = {'timestamps': [], 'count': 0}

                    packet_counts[src_ip]['timestamps'].append(datetime.now())
                    packet_counts[src_ip]['count'] += 1

                    elapsed_times = [(datetime.now() - t).total_seconds() for t in packet_counts[src_ip]['timestamps']]
                    num_packets = sum(et <= seconds for et in elapsed_times)

                    print(f"Source IP: {src_ip}")
                    print(f"Packets count: {packet_counts[src_ip]['count']}")
                    print(f"Elapsed times: {elapsed_times}")
                    print(f"Num packets: {num_packets}")
                    print(f"Threshold count: {count}")
                    print(f"Threshold seconds: {seconds}")
                    print("")

                    if num_packets >= count:
                        return True

                elif 'by_dst' in threshold_track.lower():
                    dst_ip = packet.ip.dst

                    if dst_ip not in packet_counts:
                        packet_counts[dst_ip] = {'timestamps': [], 'count': 0}

                    packet_counts[dst_ip]['timestamps'].append(datetime.now())
                    packet_counts[dst_ip]['count'] += 1

                    elapsed_times = [(datetime.now() - t).total_seconds() for t in packet_counts[dst_ip]['timestamps']]
                    num_packets = sum(et <= seconds for et in elapsed_times)

                    print(f"Destination IP: {dst_ip}")
                    print(f"Packets count: {packet_counts[dst_ip]['count']}")
                    print(f"Elapsed times: {elapsed_times}")
                    print(f"Num packets: {num_packets}")
                    print(f"Threshold count: {count}")
                    print(f"Threshold seconds: {seconds}")
                    print("")

                    if num_packets >= count:
                        return True

    return False



'''
'''
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
                            print(f"Threshold exceeded for rule: {rule['Available Option Values']}, count: {count}, source IP: {ip}")
                            if 'msg' in rule['Available Options']:
                                print(f"ALERT: {rule['Available Option Values']['msg']}")

                elif 'by_dst' in threshold_track.lower():
                    dst_ip = packet.ip.dst

                    if dst_ip not in packet_counts:
                        packet_counts[dst_ip] = []

                    packet_counts[dst_ip].append(datetime.now())

                    for ip, timestamps in packet_counts.items():
                        num_packets = sum((datetime.now() - t) <= timedelta(seconds=seconds) for t in timestamps)
                        if num_packets >= count:
                            print(f"Threshold exceeded for rule: {rule['Available Option Values']}, count: {count}, destination IP: {ip}")
                            if 'msg' in rule['Available Options']:
                                print(f"ALERT: {rule['Available Option Values']['msg']}")
'''
def check_threshold(rule, packet, packet_counts):
    alert_message = ""

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
                   #         alert_message += f"Threshold exceeded for rule: {rule['Available Option Values']}, count: {count}, source IP: {ip}\n"
                            if 'msg' in rule['Available Options']:
                                alert_message += f"ALERT: {rule['Available Option Values']['msg']}\n"

                elif 'by_dst' in threshold_track.lower():
                    dst_ip = packet.ip.dst

                    if dst_ip not in packet_counts:
                        packet_counts[dst_ip] = []

                    packet_counts[dst_ip].append(datetime.now())

                    for ip, timestamps in packet_counts.items():
                        num_packets = sum((datetime.now() - t) <= timedelta(seconds=seconds) for t in timestamps)
                        if num_packets >= count:
                    #        alert_message += f"Threshold exceeded for rule: {rule['Available Option Values']}, count: {count}, destination IP: {ip}\n"
                            if 'msg' in rule['Available Options']:
                                alert_message += f"ALERT: {rule['Available Option Values']['msg']}\n"

    return alert_message


packet_counts = {}
rules = parse_snort_rules('snort_rules.conf')
cap = pyshark.LiveCapture(interface='eth0', include_raw=True, use_json=True)

for packet in cap:
    if 'IP' not in packet:
        continue
    raw_packet = bytes(packet.get_raw_packet())
    packet_str = raw_packet.decode(errors='ignore')
    print(packet.ip.src, packet.ip.dst, packet.highest_layer)

    for rule in rules:
        alert_message = check_threshold(rule, packet, packet_counts)
        if alert_message:
            print(alert_message)

