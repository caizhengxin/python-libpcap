# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-12 11:01:25
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-12 13:07:36
# from pylibpcap.pcap import mpcap
from pylibpcap.base import LibPcap


LibPcap(in_file="/home/jankincai/bolean/raw_dnp3.pcap", out_file="pcap.pcap").mpcap()
