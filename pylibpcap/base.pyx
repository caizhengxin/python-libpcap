# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-10 12:53:07
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-12 12:51:01
import os

from pylibpcap.utils import to_c_str, from_c_str, get_pcap_file


BUFSIZ = 65535
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_ERRBUF_SIZE = 256
PCAP_IF_LOOPBACK = 0x00000001
MODE_CAPT = 0
MODE_STAT = 1


cdef class BasePcap(object):
    """
    BasePcap

    :param path: Input dir/file, default ``""``
    :param out_file: Output file, default ``""``
    :param filters: BPF Filters, default ``""``
    """

    def __cinit__(self, str path="", str out_file="", str filters="", int snaplen=65535, *args, **kwargs):
        """
        init
        """

        assert path or out_file, "path or out_file is not None."

        self.path = self._to_c_str(path)
        self.out_file = self._to_c_str(out_file)
        self.filters = self._to_c_str(filters)
        self.snaplen = snaplen

        self.in_pcap = pcap_open_offline(self.path, self.errbuf)
        self.out_in_pcap = pcap_open_offline(self.out_file, self.errbuf)
        self.out_pcap = pcap_dump_open(pcap_open_dead(1, self.snaplen), self.out_file)

    def _to_c_str(self, v):
        """
        Python str to C str
        """

        return to_c_str(v)

    def _from_c_str(self, v):
        """
        C str to Python str
        """

        return from_c_str(v)

    def get_errbuf(self):
        """
        Get errbuf
        """

        return self._from_c_str(self.errbuf)

    cdef void set_filter(self, pcap_t* p, char* filters):
        """
        Set BPF Filter
        """

        cdef bpf_program fp

        pcap_compile(p, &fp, filters, 1, 0)
        pcap_setfilter(p, &fp)
        pcap_freecode(&fp)

    cdef void pcap_write_dump(self, pcap_pkthdr pkt_header, bytes buf):
        """
        pcap write dump

        :param pkt_header: pcap_pkthdr struct.
        :param buf: bytes.
        """

        pkt_header.caplen = len(buf)
        pkt_header.len = pkt_header.caplen
        pcap_dump(<u_char*>self.out_pcap, &pkt_header, buf)

    cdef void pcap_next_dump(self, pcap_t* in_pcap, char* filters):
        """
        pcap next dump
        """

        cdef u_char* pkt
        cdef pcap_pkthdr pkt_header

        if filters:
            self.set_filter(in_pcap, filters)

        while 1:
            pkt = <u_char*>pcap_next(in_pcap, &pkt_header)

            if pkt == NULL:
                break

            pcap_dump(<u_char*>self.out_pcap, &pkt_header, pkt)

    cdef void pcap_next_dumps(self):
        """
        pcap_next_dumps
        """

        cdef pcap_t* in_pcap = NULL

        for f in get_pcap_file(self.path):
            in_pcap = pcap_open_offline(self._to_c_str(f), self.errbuf)

            if in_pcap == NULL:
                raise ValueError(self.get_errbuf())

            self.pcap_next_dump(in_pcap, self.filters)
            pcap_close(in_pcap)

    def close(self):
        """
        close
        """

        if self.out_pcap:
            pcap_dump_flush(self.out_pcap)
            pcap_dump_close(self.out_pcap)
            self.out_pcap = NULL

        if self.in_pcap:
            pcap_close(self.in_pcap)
            self.in_pcap = NULL

        if self.out_in_pcap:
            pcap_close(self.out_in_pcap)
            self.out_in_pcap = NULL

    def __dealloc__(self):
        """
        free memory
        """

        self.close()


cdef class LibPcap(BasePcap):
    """
    Pcap
    """

    def write(self, v):
        """
        Write pcap
        """

        cdef pcap_pkthdr pkt_header

        if isinstance(v, bytes):
            self.pcap_write_dump(pkt_header, v)
        else:
            for buf in v:
                if isinstance(buf, bytes):
                    self.pcap_write_dump(pkt_header, buf)

    def read(self):
        """
        Read pcap
        """

        cdef pcap_pkthdr pkt_header

        cdef u_char *pkt

        if self.filters:
            self.set_filter(self.in_pcap, self.filters)

        while 1:

            pkt = <u_char*>pcap_next(self.in_pcap, &pkt_header)

            if pkt == NULL:
                break

            yield pkt_header.caplen, pkt_header.ts.tv_sec, (<char *>pkt)[:pkt_header.caplen]

    def mpcap(self):
        """
        Merge two pcap file.
        """

        self.pcap_next_dump(self.out_in_pcap, "")
        self.pcap_next_dump(self.in_pcap, self.filters)

    def mpcaps(self):
        """
        Merge many pcap file.
        """

        self.pcap_next_dumps()


cdef class Sniff(BasePcap):
    """
    Capture packet

    :param iface: Iface
    :param count: Capture packet num, default ``-1``
    :param promisc: Promiscuous mode, default ``0``
    :param snaplen: Cut packet lenght, default ``65535``
    :param filters: BPF filter rules, default ``""``
    :param out_file: Output pcap file, default ``""``
    """

    def __cinit__(self, str iface, int count=-1, int promisc=0, int snaplen=65535,
                  str filters="", str out_file="", *args, **kwargs):
        """
        init
        """

        self.out_file = self._to_c_str(out_file)
        self.filters = self._to_c_str(filters)
        self.iface = self._to_c_str(iface)
        self.count = count
        self.handler = pcap_open_live(self.iface, snaplen, promisc, 0, self.errbuf)

        if self.handler == NULL:
            raise ValueError(self.get_errbuf())

        # Set BPF filter
        if self.filters:
            self.set_filter(self.handler, self.filters)

        self.out_pcap = pcap_dump_open(self.handler, self.out_file) if out_file else NULL

    def capture(self):
        """
        Run capture packet
        """

        cdef pcap_pkthdr pkt_header

        count = self.count

        while count == -1 or count > 0:
            pkt = <u_char*>pcap_next(self.handler, &pkt_header)

            if self.out_pcap != NULL:
                pcap_dump(<u_char*>self.out_pcap, &pkt_header, pkt)

            yield pkt_header.caplen, pkt_header.ts.tv_sec, (<char*>pkt)[:pkt_header.caplen]

            if count > 0:
                count -= 1

    def close(self):
        """
        close
        """

        if self.out_pcap != NULL:
            pcap_dump_flush(self.out_pcap)
            pcap_dump_close(self.out_pcap)
            self.out_pcap = NULL

        if self.handler != NULL:
            pcap_close(self.handler)
            self.handler = NULL
