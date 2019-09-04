# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-03 09:50:27
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-04 14:25:00
import os
import argparse

from pylibpcap.pcap import mpcaps


def get_pcap_file(path):
    """
    获取pcap文件

    :param path: path.
    """

    return (
        os.path.join(directory, file)
        for directory, dirs, files in os.walk(path)
        for file in files if ".pcap" in file
    )


def main():
    """
    merge pcap file.
    """

    parser = argparse.ArgumentParser(description="Merge pcap file.")
    parser.add_argument("filter", nargs="*", type=str, help="BPF filter rules.")
    parser.add_argument("-i", "--input", type=str, help="Input file/path.", required=True)
    parser.add_argument("-o", "--output", type=str, help="Output file.", required=True)
    args = parser.parse_args()

    print(args)

    filters = " ".join(args.filter)

    if os.path.isfile(args.input):
        mpcaps(args.input, args.output, filters)
    else:
        mpcaps(get_pcap_file(args.input), args.output, filters)
