# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 14:31:53
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-04 14:35:12
from pylibpcap.pcap import mpcaps, mpcap


# mpcap(file1，file2)
# file1 merge file2
mpcap("demo.pcap", "demo2.pcap")

# 根据BPF规则提取数据
mpcaps(
    [
        "demo.pcap",
        "demo2.pcap",
        "demo3.pcap",
        # ......
    ],
    "pcap.pcap",
    "port 502",
)
