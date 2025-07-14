# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:35:32
# @Last Modified by:   jankincai
# @Last Modified time: 2025-07-14 10:10:33
from pylibpcap.pcap import sniff


for plen, t, buf in sniff("enp2s0", count=-1, promisc=1, filters="port 53", out_file="pcap.pcap"):
    print("[+]: Payload len=", plen)
    print("[+]: Time", t)
    print("[+]: Payload", buf)
