# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-03 09:50:27
# @Last Modified by:   jankincai
# @Last Modified time: 2025-07-14 15:00:40
import argparse

from pylibpcap.base import Sniff
from pylibpcap.pcap import mpcap
from pylibpcap.open import OpenPcap
from pylibpcap.parse import Packet
from pylibpcap.exception import LibpcapError


def pylibpcap_merge():
    """
    merge pcap file.
    """

    parser = argparse.ArgumentParser(description="Merge pcap file.")
    parser.add_argument("filter", nargs="*", type=str, help="BPF filter rules.")
    parser.add_argument("-i", "--input", type=str, help="Input file/path.", required=True)
    parser.add_argument("-o", "--output", type=str, help="Output file.", required=True)
    args = parser.parse_args()

    try:
        mpcap(args.input, args.output, " ".join(args.filter))
    except KeyboardInterrupt:
        pass
    except LibpcapError as e:
        print(e)


def pylibpcap_sniff():
    """
    Capture Packet

    :param iface: Iface
    :param count: Capture packet num, default ``-1``
    :param promisc: Promiscuous mode, default ``0``
    :param snaplen: Cut packet lenght, default ``65535``
    :param filters: BPF filter rules, default ``""``
    :param out_file: Output pcap file, default ``""``
    """

    parser = argparse.ArgumentParser(description="Sniff")
    parser.add_argument("-i", "--iface", type=str, help="Specify the name of the network device.", required=True)
    parser.add_argument("-c", "--count", type=int, default=-1, help="Set the number of data packets to capture, "
                                                                    "-1 indicates continuous capture.")
    parser.add_argument("-t", "--timeout", type=int, default=0, help="Set timeout (ms).")
    parser.add_argument("--promisc", type=int, default=0, help="Set promiscuous mode.")
    parser.add_argument("--immediate-mode", type=int, default=0, help="Set immediate mode.")
    parser.add_argument("-o", "--output", type=str, help="Specify output pcap file.")
    parser.add_argument("-v", "--view", action="store_true", help="Show Packet Info.")
    parser.add_argument("-vp", "--view-payload", action="store_true", help="Show Packet Payload.")
    parser.add_argument("filter", nargs="*", type=str, help="Set BPF filter rules.")
    args = parser.parse_args()

    num = 0

    sniffobj = None

    try:
        sniffobj = Sniff(iface=args.iface, count=args.count, promisc=args.promisc,
                         filters=" ".join(args.filter), timeout=args.timeout, out_file=args.output,
                         immediate_mode=args.immediate_mode)

        for plen, t, buf in sniffobj.capture():
            if plen == 0:
                raise Exception(f"Capture timeout ({args.timeout})")
            elif args.view:
                num += 1
                print(num, Packet(buf, plen).to_string(args.view_payload))
    except KeyboardInterrupt:
        pass
    except LibpcapError as e:
        print(e)
        exit(1)

    if sniffobj is not None:
        stats = sniffobj.stats()
        print("\n")
        print(stats.capture_cnt, " packets captured")
        print(stats.ps_recv, " packets received by filter")
        print(stats.ps_drop, "  packets dropped by kernel")
        print(stats.ps_ifdrop, "  packets dropped by iface")


def pylibpcap_write():
    """Write pcap cli
    """

    parser = argparse.ArgumentParser(description="Write pcap")
    parser.add_argument("-o", "--output", type=str, required=True, help="File path.")
    parser.add_argument("payload", nargs=1, type=str, help="Payload")
    args = parser.parse_args()

    try:
        with OpenPcap(args.output, "a") as f:
            f.write(bytes.fromhex(args.payload[0]))
    except KeyboardInterrupt:
        pass
    except LibpcapError as e:
        print(e)


def pylibpcap_read():
    """Read pcap cli
    """

    parser = argparse.ArgumentParser(description="Read pcap")
    parser.add_argument("-i", "--input", type=str, required=True, help="File path.")
    parser.add_argument("filter", nargs="*", type=str, help="BPF filter rules")
    parser.add_argument("-v", "--view", action="store_true", help="Show Packet Info")
    parser.add_argument("-p", "--view-payload", action="store_true", help="Show Payload")
    args = parser.parse_args()

    num = 0

    try:
        with OpenPcap(args.input, "r", filters=" ".join(args.filter)) as f:
            for plen, t, buf in f.read():
                num += 1

                if args.view:
                    print(Packet(buf, plen).to_string(args.view_payload))
    except KeyboardInterrupt:
        pass
    except LibpcapError as e:
        print(e)
        exit(1)

    print("\nPacket Count:", num)
