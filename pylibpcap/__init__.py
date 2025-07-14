# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-11-09 14:57:10
# @Last Modified by:   jankincai
# @Last Modified time: 2025-07-14 10:13:28

__version__ = "0.5.3"
__author__ = "JanKinCai"
__all__ = [
    "rpcap",
    "wpcap",
    "mpcap",
    "sniff",
    "get_first_iface",
    "get_iface_list",
    "send_packet",
    "LibPcap",
    "Sniff",
    "OpenPcap",
]


try:
    from pylibpcap.pcap import rpcap, wpcap, mpcap, sniff
    from pylibpcap.base import get_first_iface, get_iface_list, send_packet
    from pylibpcap.base import LibPcap, Sniff
    from pylibpcap.open import OpenPcap
except ImportError:
    pass
