# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:26:41
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-04 14:27:23
from pylibpcap.pcap import rpcap


buf = b'\x00\xc0\x9f2A\x8c\x00\xe0\x18\xb1\x0c\xad\x08\x00E\x00\x008' \
      b'\x00\x00@\x00@\x11eG\xc0\xa8\xaa\x08\xc0\xa8\xaa\x14\x80\x1b' \
      b'\x005\x00$\x85\xed\x102\x01\x00\x00\x01\x00\x00\x00\x00\x00' \
      b'\x00\x06google\x03com\x00\x00\x10\x00\x01'


for len, t, pkt in rpcap("tests/dns.pcap"):
    print("字节流长度：", len)
    print("捕获时间：", t)
    print("字节流：", pkt)
