# -*- coding: utf-8 -*-

__version__ = "0.1.2"
__author__ = "JanKinCai"
__all__ = [
    "rpcap",
    "wpcap",
    "mpcap",
    "sniff",
    "get_first_iface",
]


try:
    from pylibpcap.pcap import rpcap, wpcap, mpcap, sniff, get_first_iface
    from pylibpcap.open import OpenPcap
except ImportError:
    pass
