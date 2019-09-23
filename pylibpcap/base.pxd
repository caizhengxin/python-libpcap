# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-10 16:30:22
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-12 12:34:38
from pylibpcap.pcap cimport *


cdef class BasePcap(object):
    """
    BasePcap
    """

    cdef bytes path
    cdef bytes out_file
    cdef bytes filters
    cdef bytes iface
    cdef int snaplen
    cdef str mode
    cdef int count
    cdef char errbuf[256]

    cdef pcap_dumper_t *out_pcap
    cdef pcap_t* in_pcap
    cdef pcap_t* out_in_pcap
    cdef pcap_t* handler

    cdef void set_filter(self, pcap_t* p, char* filters)

    cdef void pcap_write_dump(self, pcap_pkthdr pkt_header, bytes buf)

    cdef void pcap_next_dump(self, pcap_t* in_pcap, char* filters)

    cdef void pcap_next_dumps(self)
