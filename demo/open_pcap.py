# @Author: JanKinCai
# @Date:   2019-09-11 17:43:19
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-12 09:27:39


from pylibpcap.open import OpenPcap


with OpenPcap("pcap.pcap", filters="port 80") as f:
    with OpenPcap("pcap2.pcap", mode="a") as f1:
        for lens, t, buf in f.read():
            # print("[+]: Buf length", lens)
            # print("[+]: Time", t)
            # print("[+]: Buf", buf)
            f1.write(buf)
