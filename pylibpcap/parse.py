
import socket


ethernet_type_map = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}


ip_type_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    8: "EGP",
    9: "IGP",
    17: "UDP",
    58: "ICMPv6"
}


def parse_mac(mac: bytes) -> str:
    """MAC
    """

    return f"{mac[0]:02x}:{mac[1]:02x}:{mac[2]:02x}:{mac[3]:02x}:{mac[4]:02x}:{mac[5]:02x}"


def parse_ipv4(addr: bytes) -> str:
    """IPv4
    """

    return f"{addr[0]}.{addr[1]}.{addr[2]}.{addr[3]}"


def parse_ipv6(addr: bytes) -> str:
    """IPv6
    """

    return socket.inet_ntop(socket.AF_INET6, addr)


def parse_int(val: bytes) -> int:
    """Bytes to int
    """

    return int.from_bytes(val, byteorder="big")


def to_hex_string(buf: bytes) -> str:
    """Hex String
    """

    hexstrlist = []
    strlist = []

    for i, v in enumerate(buf):
        if i % 16 == 0:
            hexstrlist.append("  ")
            hexstrlist.extend(strlist)
            strlist.clear()
            hexstrlist.append("\n")

        if 0x21 <= v <= 0x7E:
            strlist.append(chr(v))
        else:
            strlist.append(".")

        hexstrlist.append(f"{v:02x}")

        if (i + 1) % 16 != 0:
            hexstrlist.append(" ")
        if (i + 1) % 8 == 0:
            strlist.append(" ")

    return "".join(hexstrlist)


class Packet(object):
    """Packet
    """

    def __init__(self, buf: bytes, buflen: int, *args, **kwargs):
        """init
        """

        self.buf = buf
        self.buflen = buflen

        self.smac = None
        self.dmac = None
        self.src = None
        self.dst = None
        self.sport = None
        self.dport = None
        self.proto = None
        self.protoid = None

        self.parse()

    def parse(self) -> None:
        """parse
        """

        self.parse_eth()

    def parse_eth(self) -> None:
        """Ethernet
        """

        if self.buflen < 14:
            return None

        buf = self.buf

        self.dmac = parse_mac(buf[:6])
        self.smac = parse_mac(buf[6:12])

        self.protoid = parse_int(buf[12:14])
        self.proto = ethernet_type_map.get(self.protoid)

        self.buf = buf[14:]
        self.buflen -= 14

        self.parse_ip()

    def parse_ip(self) -> None:
        """IPv4 and IPv6
        """

        if self.protoid == 0x0800:
            self.parse_ipv4()
        elif self.protoid == 0x86dd:
            self.parse_ipv6()

    def parse_ipv6(self) -> None:
        """IPv6
        """

        if self.buflen < 40:
            return None

        buf = self.buf

        plen = parse_int(buf[4:6])

        self.protoid = buf[6]
        self.src = parse_ipv6(buf[8:24])
        self.dst = parse_ipv6(buf[24:40])
        self.proto = ip_type_map.get(self.protoid) or self.proto

        self.buf = self.buf[plen:]
        self.buflen -= plen

    def parse_ipv4(self) -> None:
        """IPv4
        """

        if self.buflen < 20:
            return None

        buf = self.buf

        iphd_len = (buf[0] & 0x0f) << 2
        # total_len = parse_int(buf[2:4])

        self.src = parse_ipv4(buf[12:16])
        self.dst = parse_ipv4(buf[16:20])
        self.protoid = buf[9]
        self.proto = ip_type_map.get(self.protoid) or self.proto

        self.buf = self.buf[iphd_len:]
        self.buflen -= iphd_len

        self.parse_tran()

    def parse_tran(self) -> None:
        """UDP and TCP
        """

        if self.protoid == 6:
            self.parse_tcp()
        elif self.protoid == 17:
            self.parse_udp()

    def parse_tcp(self) -> None:
        """TCP
        """

        if self.buflen < 20:
            return None

        buf = self.buf

        self.sport = parse_int(buf[:2])
        self.dport = parse_int(buf[2:4])
        self.proto = "TCP"

        tcplen = buf[12] >> 2

        self.buf = self.buf[tcplen:]
        self.buflen -= tcplen

    def parse_udp(self) -> None:
        """UDP
        """

        if self.buflen < 8:
            return None

        buf = self.buf

        self.sport = parse_int(buf[:2])
        self.dport = parse_int(buf[2:4])
        self.proto = "UDP"

        udplen = parse_int(buf[4:6]) - 8

        self.buf = self.buf[udplen:]
        self.buflen -= udplen

    def to_string(self) -> None:
        """To string
        """

        pktinfolist = []

        if self.smac is not None:
            pktinfolist.append(self.smac)

        if self.src is not None:
            pktinfolist.append(self.src)

        if self.sport is not None:
            pktinfolist.append(str(self.sport))

        pktinfolist.append("->")

        if self.dmac is not None:
            pktinfolist.append(self.dmac)

        if self.dst is not None:
            pktinfolist.append(self.dst)

        if self.dport is not None:
            pktinfolist.append(str(self.dport))

        if self.proto is not None:
            pktinfolist.append(str(self.proto))

        pktinfolist.append(to_hex_string(self.buf))

        return " ".join(pktinfolist)

    def __repr__(self) -> None:
        """repr
        """

        return self.to_string()

    def __str__(self) -> None:
        """str
        """

        return self.to_string()


if __name__ == "__main__":
    buf = b"\xac\x64\x17\x5f\xfa\x41\x00\x0e\xc6\xc9\x15\x7e\x08\x00\x45\x00" \
          b"\x00\x4b\x8a\x58\x40\x00\x80\x06\x00\x00\xc0\xa8\x00\x02\xc0\xa8" \
          b"\x00\x01\xc7\x99\x00\x66\x2f\xfd\xf7\x65\xb7\x0c\x4e\xef\x50\x18" \
          b"\xfa\xf0\x81\x91\x00\x00\x03\x00\x00\x23\x1e\xe0\x00\x00\x00\x1e" \
          b"\x00\xc1\x02\x06\x00\xc2\x0f\x53\x49\x4d\x41\x54\x49\x43\x2d\x52" \
          b"\x4f\x4f\x54\x2d\x45\x53\xc0\x01\x0a"

    obj = Packet(buf, len(buf))
    print(obj)

    buf = b"\x00\xd0\x03\xb3\xa7\xfc\x00\x13\x72\x97\xa2\xd4\x08\x00\x45\x00" \
          b"\x00\x2e\x82\x2b\x40\x00\x40\x11\x13\x26\x0a\x04\x0e\x66\x0a\x82" \
          b"\x82\x82\xe5\x62\x25\x80\x00\x1a\xfe\x53\x80\x00\x02\x00\x00\x00" \
          b"\x00\x00\x00\x7a\x01\x01\x00\xcc\xcc\xcc\x00\x01"

    obj = Packet(buf, len(buf))
    print(obj)

    buf = b"\xc2\x01\x51\xfa\x00\x00\xc2\x00\x51\xfa\x00\x00\x86\xdd\x60\x00" \
          b"\x00\x00\x00\x3c\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x12\x00\x00" \
          b"\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x12\x00\x00" \
          b"\x00\x00\x00\x00\x00\x02\x80\x00\x86\x3c\x11\x0d\x00\x00\x00\x01" \
          b"\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11" \
          b"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21" \
          b"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31" \
          b"\x32\x33"

    obj = Packet(buf, len(buf))
    print(obj)
