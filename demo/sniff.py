# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:35:32
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-04 14:36:05
from pylibpcap.pcap import sniff


for lens, t, buf in sniff("enp2s0", strs="port 53", count=3, out_file="pcap.pcap"):
    print("字节流长度：", lens)
    print("捕获时间：", t)
    print("字节流：", buf)
