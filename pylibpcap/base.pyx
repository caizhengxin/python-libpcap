# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-10 12:53:07
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-10 18:08:10
from pylibpcap.utils import to_c_name


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

    :param in_file: Input file, default ``""``
    :param out_file: Output file, default ``""``
    :param filters: BPF Filters, default ``""``
    """

    def __cinit__(self, str in_file="", str out_file="", filters="", buf_size=65535, *args, **kwargs):
        """
        init
        """

        assert in_file or out_file, "in_file or out_file is not None."

        self.in_file = self.to_c_str(in_file)
        self.out_file = self.to_c_str(out_file)
        self.filters = self.to_c_str(filters)
        self.buf_size = buf_size
        self.in_pcap = pcap_open_dead(1, self.buf_size) if not in_file else pcap_open_offline(self.in_file, self.errbuf)

        if self.in_pcap == NULL:
            raise ValueError(self.get_errbuf())

        self.out_pcap = pcap_dump_open(self.in_pcap, self.out_file)

    def to_c_str(self, v):
        """
        Python str to C str
        """

        return v.encode("utf-8")

    def from_c_str(self, v):
        """
        C str to Python str
        """

        return v.decode("utf-8")

    def get_errbuf(self):
        """
        Get errbuf
        """

        return self.from_c_str(self.errbuf)

    cdef void set_filter(self, pcap_t* p, char* filters):
        """
        Set BPF Filter
        """

        cdef bpf_program fp

        pcap_compile(p, &fp, filters, 1, 0)
        pcap_setfilter(p, &fp)
        pcap_freecode(&fp)

    cdef void pcap_dump(self, pcap_pkthdr pkt_header, bytes buf):
        """
        pcap dump

        :param pkt_header: pcap_pkthdr struct.
        :param buf: bytes.
        """

        pkt_header.caplen = len(buf)
        pkt_header.len = pkt_header.caplen
        pcap_dump(<u_char*>self.out_pcap, &pkt_header, buf)

    cpdef void write(self, object pkt):
        """
        Write pcap
        """

        cdef pcap_pkthdr pkt_header

        if isinstance(pkt, bytes):
            self.pcap_dump(pkt_header, pkt)
        else:
            for buf in pkt:
                if isinstance(buf, bytes):
                    self.pcap_dump(pkt_header, buf)

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

    def __enter__(self):
        """
        enter
        """

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        exit
        """

        self.__dealloc__()

    def __dealloc__(self):
        """
        free memory
        """

        if self.out_pcap:
            pcap_dump_flush(self.out_pcap)
            pcap_dump_close(self.out_pcap)

        if self.in_pcap:
            pcap_close(self.in_pcap)
