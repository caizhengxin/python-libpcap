# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:31:53
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-04 23:32:54
from pylibpcap.pcap import mpcaps, mpcap


# mpcap(file1，file2)
# file1合并到file2
mpcap("demo.pcap", "demo2.pcap")

# 根据BPF规则提取数据，并输出到output.pcap
mpcaps("pcap/", "output.pcap", "port 502")
