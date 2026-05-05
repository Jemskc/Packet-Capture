import os
import sys
import argparse
import pyshark

DESCRIPTION = """\
Packet Capture & IDS — capture live traffic or analyze a PCAP file against Snort-style rules.

Usage:
  python main.py -i <interface>       live capture
  python main.py -o <file.pcap>       analyze saved capture
"""


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('-i', '--interface',         metavar='', help='Network interface for live capture (e.g. eth0)')
    parser.add_argument('-o', '--open',              metavar='', help='Path to a .pcap or .pcapng file')
    parser.add_argument('-s', '--save_file',         metavar='', help='Save live capture to a PCAP file')
    parser.add_argument('-n', '--number_of_packets', metavar='', type=int, help='Stop after N packets')
    parser.add_argument('-p', '--protocol',          metavar='', help='Filter by protocol (e.g. tcp, http)')
    parser.add_argument('-v', '--verbose',           action='store_true', help='Print full packet layer details')
    return parser


def open_capture(args):
    """Validate arguments and return an open pyshark capture object."""
    if not args.interface and not args.open:
        print('Error: provide -i (interface) or -o (pcap file).')
        sys.exit(1)

    if args.open:
        ext = os.path.splitext(args.open)[1].lower()
        if ext not in ('.pcap', '.pcapng'):
            print('Error: file must be .pcap or .pcapng')
            sys.exit(1)
        try:
            return pyshark.FileCapture(args.open), args
        except FileNotFoundError:
            print('Error: file not found.')
            sys.exit(1)

    try:
        return pyshark.LiveCapture(interface=args.interface, output_file=args.save_file), args
    except pyshark.capture.live_capture.UnknownInterfaceException:
        print(f"Error: interface '{args.interface}' not found or inaccessible.")
        sys.exit(1)


def print_header():
    fmt = '{:<35} {:<15} {:<20} {:<15} {:<20} {:<15}'
    print(fmt.format('Time', 'Protocol', 'Source IP', 'Src Port', 'Destination IP', 'Dst Port'))
    print('-' * 126)


def run_capture(packet_handler):
    """Parse CLI args, open the capture source, and call packet_handler for each packet."""
    parser = build_arg_parser()
    args = parser.parse_args()
    capture, args = open_capture(args)

    print_header()

    packets = (
        capture
        if args.open
        else capture.sniff_continuously(packet_count=args.number_of_packets)
    )

    for i, packet in enumerate(packets):
        if args.number_of_packets and i >= args.number_of_packets:
            break
        if args.protocol and packet.highest_layer.lower() != args.protocol.lower():
            continue
        packet_handler(packet)
        if args.verbose:
            print(packet)
