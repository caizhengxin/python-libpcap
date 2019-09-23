# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-05-10 11:46:33
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-12 13:28:50
import os

from pylibpcap.utils import get_pcap_file, to_c_str, from_c_str
from pylibpcap.base import Sniff, LibPcap, PCAP_ERRBUF_SIZE


cpdef str get_first_iface():
    """
    Get first iface
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef char* iface

    iface = pcap_lookupdev(errbuf)

    return from_c_str(iface) if iface else ""


def rpcap(str path, str filters=""):
    """
    Read pcap file.

    :param path: 文件路径.
    :param filters: BPF Filters

    return tuple: (Buf length，Capture time，Buf)
    """

    with OpenPcap(path, filters=filters) as f:
        return f.read()

cpdef void wpcap(object v, str path):
    """
    Write pcap file.

    :param v: Buf/Buf(list)
    :param out_file: Output file
    """

    with OpenPcap(path, "a") as f:
        f.write(v)


cpdef void mpcap(str path, str out_file, str filters=""):
    """
    Merge many pcap file.

    :param path: Input dir/file
    :param out_file: Output file
    :param filters: BPF Filters, default ``""``
    """

    with OpenPcap(out_file, "a") as f:
        if os.path.isdir(path):
            for p in path:
                f.write(rpcap(p, filters))
        else:
            f.write(rpcap(path, filters))


# cdef void sniff_callback(u_char *user, const pcap_pkthdr *pkt_header, const u_char *pkt_data):
#     """
#     捕获数据包回调函数
#     """

#     if user != NULL:
#         pcap_dump(user, pkt_header, pkt_data)


def sniff(*args, **kwargs):
    """
    Capture packet

    :param iface: Iface
    :param count: Capture packet num, default ``-1``
    :param promisc: Promiscuous mode, default ``0``
    :param snaplen: Cut packet lenght, default ``65535``
    :param filters: BPF filter rules, default ``""``
    :param out_file: Output pcap file, default ``""``
    """

    return Sniff(*args, **kwargs).capture()
