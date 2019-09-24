# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:31:53
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-04 23:32:54
from pylibpcap.pcap import mpcap


mpcap("demo.pcap", "demo2.pcap")

mpcap("pcap/", "output.pcap", "port 502")
