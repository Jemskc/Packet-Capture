#!/usr/bin/python

import argparse
import pyshark


def live_capture(interface, num_packets=None, tcp=False, protocol=None, save_file=None, verbose=False):
    # create the argument parser
    parser = argparse.ArgumentParser(description='A simple PyShark example that captures live packets from a network interface.')

    # add the command line options
    parser.add_argument('-i', '--interface', type=str, default=None, help='Network interface to capture packets from')
    parser.add_argument('-n', '--num_packets', type=int, default=None, help='Limit number of packets to capture')
    parser.add_argument('-t', '--tcp', action='store_true', help='Show only TCP packets')
    parser.add_argument('-p', '--protocol', type=str, default=None, help='Filter packets by protocol')
    parser.add_argument('-s', '--save_file', type=str, default=None, help='Save captured packets to a pcap file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed packet information')
    # parse the command line arguments
    args = parser.parse_args()

    try:
        # check if the user specified a network interface
        if args.interface:
            interface = args.interface
        else:
            raise ValueError("Missing network interface, please specify with -i option")

        # check if the user specified a save file
        if args.save_file:
            save_file = args.save_file

        # create the live capture object
        capture = pyshark.LiveCapture(interface=interface)

        # apply the filters
        if args.tcp:
            capture.filter('tcp')
        if args.protocol:
            capture.filter(args.protocol)

        # start capturing packets
        for i, packet in enumerate(capture.sniff_continuously(packet_count=args.num_packets)):
            if args.num_packets and i >= args.num_packets:
                break

            if verbose:
                print(packet)

            if save_file:
                with open(save_file, 'ab') as f:
                    f.write(bytes(packet))

    except AttributeError as e:
        print(f"Error: tshark not found. Please install tshark or make sure it's in your PATH")
        exit()
    except AttributeError as e:
        print(f"Error: permission denied. Please run this program as root or administrator")
        exit()
    except AttributeError as e:
        print(f"Error: invalid network interface. Please specify a valid network interface.")
        print(f"Available network interfaces: {pyshark.LiveCapture.list_interfaces()}")
        exit()
    except Exception as e:
        print("Error occurred:", e)
        exit()

# example usage
live_capture(interface, num_packets=None, tcp=False, protocol=None, save_file=None, verbose=False)

