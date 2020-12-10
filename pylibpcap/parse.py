
import datetime
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


def parse_tcp_flags(val: int) -> str:
    """TCP Flags
    """

    flagslist = []

    if val & 0x0002:
        flagslist.append("SYN")

    if val & 0x0010:
        flagslist.append("ACK")

    if val & 0x0008:
        flagslist.append("PUSH")

    if val & 0x0004:
        flagslist.append("RST")

    if val & 0x0001:
        flagslist.append("FIN")

    return ",".join(flagslist)


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
            hexstrlist.append("\n" + " " * 5)

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
        self.tcp_flags = None

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

        self.tcp_flags = parse_tcp_flags(parse_int(buf[12:14]) & 0x0fff)

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

    def to_string(self, show_payload: bool = False) -> str:
        """To string
        """

        pktinfolist = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")]

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

        if self.tcp_flags is not None:
            pktinfolist.append(self.tcp_flags)

        if show_payload:
            pktinfolist.append("\n")
            pktinfolist.append(to_hex_string(self.buf))
            pktinfolist.append("\n")

        return " ".join(pktinfolist)

    def __repr__(self) -> None:
        """repr
        """

        return self.to_string(True)

    def __str__(self) -> None:
        """str
        """

        return self.to_string(True)
