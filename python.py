
#!/usr/bin/python

import argparse
import pyshark
import time
import re as regex
import sqlite3


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', metavar=" ", type=str, required = True, help = 'To specify the interface ')
parser.add_argument('-v', '--verbose', required = False, action = 'store_true', help = 'To print the all layer of packet')
parser.add_argument('-o', '--output', metavar=' ', help = 'To capture and save the pcap in a file')
parser.add_argument('-p', '--protocol', metavar=' ', help= 'To capture packet using ptotocl filter')
parser.add_argument('-u', '--udp', action = 'store_true', help = 'To capture udp packet only')
parser.add_argument('-t', '--tcp', action = 'store_true', help = 'To capture tcp packet only')
parser.add_argument('-c', '--count', metavar=' ',type=int, default=1,  help = 'To capture limited number of packet')

args = parser.parse_args()


###################### Connect to the database file or create a new one if it doesn't exist #######
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

# Create a table for the packets if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS packets (
                time TEXT, protocol TEXT, src_addr TEXT, dst_addr TEXT, src_port INTEGER, dst_port INTEGER)''')

############################################################## parsing snort rule #########################################################



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

    rule_alert = rule['Alert']
    content_matches = []
    for option in content_options:
        value = option['content']
        value = value.strip('"')
        if value.lower() in str(packet_content).lower():
            content_matches.append(value)

    if len(content_options) > 0 and len(content_matches) == len(content_options):
        return f'Alert: Rule "{rule_alert}" triggered, all content options match'
    elif len(content_options) > 0 and len(content_matches) < len(content_options):
        return f'Alert: Rule "{rule_alert}" not triggered, not all content options match'
    
    return f'Rule "{rule_alert}" does not have any content options'

################################################################################ storing alerts in a file name alert.log #####################################################

def run_alert(msg):

    with open('alert.log', 'a') as f:
         f.write(alert_msg + '\n')



########################### parsing protocol argparse ###########################################
if args.protocol:
   capture = pyshark.LiveCapture(interface=args.interface, display_filter=args.protocol)


elif args.udp:
   capture = pyshark.LiveCapture(interface=args.interface, bpf_filter='udp')

elif args.tcp:
   capture = pyshark.LiveCapture(interface=args.interface, bpf_filter='tcp')

else:
   capture = pyshark.LiveCapture(interface=args.interface,use_json=True, include_raw=True, output_file=args.output)
#   capture.sniff(packet_count = args.count)


parsed_rules = parse_snort_rules('snort_rules.conf')

for packet in capture.sniff_continuously():
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
    print (localtime, '\t', packet_protocol, '\t', packet_src, '\t', packet_sport, '\t', packet_dst,'\t', packet_dport)
    print(packet_content)
    packet_options = []
    for layer in packet.layers:
        if layer.layer_name == 'Snort':
            for field in layer.fields:
                if field.startswith('Snort '):
                    option_name, option_value = field[len('Snort '):].split(':', 1)
                    packet_options.append({option_name.strip(): option_value.strip()})
    for rule in parsed_rules:
        if (match_protocol(packet_protocol, rule['Protocol']) and
            match_direction(packet_src, packet_dst, rule['Source Address'], rule['Destination Address'], rule['Direction']) and
            match_address(packet_src, rule['Source Address']) and
            match_address(packet_dst, rule['Destination Address']) and
            match_port(packet_sport, rule['Source Port']) and
            match_port(packet_dport, rule['Destination Port'])and
            match_content(rule['Available Option Values']['content'], packet_content)):
            for option in rule['Options']:
                
                if 'msg' in option.keys():
                    print(option['msg'])
              #  if option in packet_options:
               #     print(f"Packet matched rule with option {option}")
                #else:
                 #   print(f"Packet matched rule {rule}")



    if args.verbose:
       print(packet.show())

##################################### for database ###########################################

    cursor.execute("INSERT INTO packets VALUES (?,?,?,?,?,?)", (localtime,packet_protocol,packet_src,packet_dst,packet_sport,packet_dport))
    conn.commit()

conn.close()

