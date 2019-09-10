# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-10 16:30:22
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-10 18:05:13
from pylibpcap.pcap cimport *


cdef class BasePcap(object):
    """
    BasePcap
    """

    cdef bytes in_file
    cdef bytes out_file
    cdef bytes filters
    cdef int buf_size
    cdef char errbuf[256]

    cdef pcap_dumper_t *out_pcap
    cdef pcap_t* in_pcap

    cdef void set_filter(self, pcap_t* p, char* filters)

    cdef void pcap_dump(self, pcap_pkthdr pkt_header, bytes buf)

    cpdef void write(self, object pkt)
