# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-03 09:50:27
# @Last Modified by:   JanKinCai
# @Last Modified time: 2020-01-13 15:38:43
import argparse

from pylibpcap.pcap import mpcap, sniff
from pylibpcap.open import OpenPcap


def main():
    """
    merge pcap file.
    """

    parser = argparse.ArgumentParser(description="Merge pcap file.")
    parser.add_argument("filter", nargs="*", type=str, help="BPF filter rules.")
    parser.add_argument("-i", "--input", type=str, help="Input file/path.", required=True)
    parser.add_argument("-o", "--output", type=str, help="Output file.", required=True)
    args = parser.parse_args()

    print("[+]:", args)

    mpcap(args.input, args.output, " ".join(args.filter))


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
    parser.add_argument("-i", "--iface", type=str, help="Iface", required=True)
    parser.add_argument("-c", "--count", type=int, default=-1, help="Capture packet num")
    parser.add_argument("-m", "--promisc", type=int, default=0, help="Promiscuous mode")
    parser.add_argument("filter", nargs="*", type=str, help="BPF filter rules")
    parser.add_argument("-o", "--output", type=str, help="Output pcap file")
    parser.add_argument("-v", "--view", action="store_true", help="是否显示")
    args = parser.parse_args()

    print("[+]:", args)

    num = 0

    try:
        for plen, t, buf in sniff(iface=args.iface, count=args.count, promisc=args.promisc,
                                  filters=" ".join(args.filter), out_file=args.output):
            num += 1

            if args.view:
                print("[+]: Payload len=", plen)
                print("[+]: Time", t)
                print("[+]: Payload", buf)
    except KeyboardInterrupt:
        pass

    print("\nPacket Count:", num)


def write_pcap_cli():
    """Write pcap cli
    """

    parser = argparse.ArgumentParser(description="Write pcap")
    parser.add_argument("-i", "--input", type=str, help="File path.")
    parser.add_argument("payload", nargs=1, type=str, help="Payload")
    args = parser.parse_args()

    path = args.input or "pcap.pcap"

    with OpenPcap(path, "a") as f:
        f.write(bytes.fromhex(args.payload[0]))
