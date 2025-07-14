# -*- coding: utf-8 -*-
# @Author: jankincai
# @Date:   2025-07-14 09:20:46
# @Last Modified by:   jankincai
# @Last Modified time: 2025-07-14 09:58:47
# https://github.com/caizhengxin/python-libpcap/issues/24
# sudo ip link add type veth
# sudo ip link set veth0 up
from pylibpcap.base import Sniff
from pylibpcap.exception import LibpcapError
from threading import Thread
import time


class MyThread(Thread):
    def run(self):
        self.max_looptime = 0
        st = time.time()
        while True:
            tnow = time.time()
            self.max_looptime = max(self.max_looptime, tnow - st)
            st = tnow
            time.sleep(0.001)


thread = MyThread(daemon=True)
thread.start()

sniffobj = None

try:
    sniffobj = Sniff("veth0", count=-1, promisc=1)

    for plen, t, buf in sniffobj.capture():
        if plen == 0:
            print("Capture timeout")
        else:
            print("[+]: Payload len=", plen)
            print("[+]: Time", t)
            print("[+]: Payload", buf)
except KeyboardInterrupt:
    pass
except LibpcapError as e:
    print(e)

if sniffobj is not None:
    stats = sniffobj.stats()
    print(stats.capture_cnt, " packets captured")
    print(stats.ps_recv, " packets received by filter")
    print(stats.ps_drop, "  packets dropped by kernel")
    print(stats.ps_ifdrop, "  packets dropped by iface")
    print("Longest loop time in thread ", thread.max_looptime)