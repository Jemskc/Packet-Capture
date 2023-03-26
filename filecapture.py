#!/usr/bin/python

import argparse
import pyshark

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

print_pcap_packets(src=False, dst=False, num_packets=None, tcp=False, file_name=None)
