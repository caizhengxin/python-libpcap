# -*- coding: utf-8 -*-

__version__ = "0.1.0"
__author__ = "JanKinCai"
__all__ = [
    "rpcap",
    "wpcap",
    "mpcap",
    "sniff",
    "get_first_iface",
]


try:
    from pylibpcap.pcap import rpcap, wpcap, mpcap, mpcaps, sniff, get_first_iface
except ImportError:
    pass
