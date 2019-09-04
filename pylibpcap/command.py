# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-03 09:50:27
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-04 23:44:17
import argparse

from pylibpcap.pcap import mpcaps


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

    mpcaps(args.input, args.output, " ".join(args.filter))
