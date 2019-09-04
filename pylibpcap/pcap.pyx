# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-05-10 11:46:33
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-04 12:29:50
# from libc.stdlib cimport free
# from libc.string cimport strdup, memcpy


# 宏定义
DEF BUFSIZ = 65535
DEF PCAP_VERSION_MAJOR = 2
DEF PCAP_VERSION_MINOR = 4
DEF PCAP_ERRBUF_SIZE = 256  # libpcap错误信息缓存的大小
DEF PCAP_IF_LOOPBACK = 0x00000001
DEF MODE_CAPT = 0  # 捕捉模式，在调用pcap_setmode()时被使用
DEF MODE_STAT = 1  # 统计模式，在调用pcap_setmode()时被使用


cdef void set_filter(pcap_t* p, char* filters):
    """
    设置过滤规则(BPF)

    :param p: pcap_t结构体
    :param filters: BPF过滤规则
    """

    cdef bpf_program fp

    pcap_compile(p, &fp, filters, 1, 0)
    pcap_setfilter(p, &fp)
    pcap_freecode(&fp)


cdef void py_pcap_dump(pcap_pkthdr pkt_header, bytes buf, pcap_dumper_t *out_pcap):
    """
    写入文件
    """

    pkt_header.caplen = len(buf)
    pkt_header.len = len(buf)
    pcap_dump(<u_char*>out_pcap, &pkt_header, buf)


cdef void py_pcap_rw(str file, pcap_pkthdr pkt_header, pcap_dumper_t *out_pcap, str filters=""):
    """
    读取文件并写入

    :param file: 文件
    :param pkt_header: pkt header
    :param out_pcap: 输出文件
    :param filters: BPF过滤规则
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef u_char *pkt
    cdef pcap_t *in_pcap = pcap_open_offline(file.encode("utf-8"), errbuf)

    if in_pcap == NULL:
        raise ValueError(errbuf.decode("utf-8"))

    if filters:
        set_filter(in_pcap, filters.encode("utf-8"))

    while 1:
        pkt = <u_char*>pcap_next(in_pcap, &pkt_header)

        if pkt == NULL:
            break

        pcap_dump(<u_char*>out_pcap, &pkt_header, pkt)

    pcap_close(in_pcap)


cpdef str get_first_iface():
    """
    返回系统中第一个合法的设备
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef char* iface

    iface = pcap_lookupdev(errbuf)

    return iface.decode("utf-8") if iface else ""


def rpcap(str file, str filters=""):
    """
    读取pcap

    :param file: 文件.
    :param filters: 过滤规则

    return tuple: (字节流长度，捕获时间，字节流)
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]

    cdef pcap_pkthdr pkt_header

    cdef u_char *pkt

    cdef pcap_t* in_pcap = pcap_open_offline(file.encode("utf-8"), errbuf)

    if in_pcap == NULL:
        raise ValueError(errbuf.decode("utf-8"))

    if filters:
        set_filter(in_pcap, filters.encode("utf-8"))

    while 1:

        pkt = <u_char*>pcap_next(in_pcap, &pkt_header)

        if pkt == NULL:
            break

        yield pkt_header.caplen, pkt_header.ts.tv_sec, (<char *>pkt)[:pkt_header.caplen]

    pcap_close(in_pcap)


cpdef void wpcap(object pkt, str out_file):
    """
    写入Pcap文件

    :param pkt: 字节流/字节流list
    :param out_file: 文件
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef pcap_pkthdr pkt_header

    cdef pcap_t* in_pcap = pcap_open_dead(1, BUFSIZ)
    cdef pcap_dumper_t *out_pcap = pcap_dump_open(in_pcap, out_file.encode("utf-8"))

    if isinstance(pkt, bytes):
        py_pcap_dump(pkt_header, pkt, out_pcap)
    elif isinstance(pkt, (list, tuple)):
        for buf in pkt:
            if isinstance(buf, bytes):
                py_pcap_dump(pkt_header, buf, out_pcap)

    pcap_dump_flush(out_pcap)
    pcap_dump_close(out_pcap)
    pcap_close(in_pcap)


cpdef void mpcap(str sfile, str dfile, str filters=""):
    """
    合并pcap文件

    :param sfile: 源文件
    :param dfile: 目的文件
    :param filters: BPF过滤规则
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef pcap_pkthdr pkt_header
    cdef u_char *pkt
    cdef pcap_dumper_t *out_pcap

    cdef pcap_t *in_pcap = pcap_open_offline(dfile.encode("utf-8"), errbuf)

    if in_pcap == NULL:
        raise ValueError(errbuf.decode("utf-8"))

    out_pcap = pcap_dump_open(in_pcap, dfile.encode("utf-8"))

    while 1:
        pkt = <u_char*>pcap_next(in_pcap, &pkt_header)

        if pkt == NULL:
            break

        pcap_dump(<u_char*>out_pcap, &pkt_header, pkt)

    pcap_close(in_pcap)

    py_pcap_rw(sfile, pkt_header, out_pcap, filters)

    pcap_dump_flush(out_pcap)
    pcap_dump_close(out_pcap)


cpdef void mpcaps(object file_obj, str out_file, str filters=""):
    """
    提取文件共同内容并存入pcap文件

    :param file_obj: 文件对象.
    :param out_file: 输出文件.
    :param filters: 过滤规则.
    """

    cdef pcap_pkthdr pkt_header
    cdef pcap_dumper_t *out_pcap = pcap_dump_open(pcap_open_dead(1, BUFSIZ), out_file.encode("utf-8"))

    if isinstance(file_obj, str):
        py_pcap_rw(file_obj, pkt_header, out_pcap, filters)
    else:
        for f in file_obj:
            py_pcap_rw(f, pkt_header, out_pcap, filters)

    pcap_dump_flush(out_pcap)
    pcap_dump_close(out_pcap)


# cdef void sniff_callback(u_char *user, const pcap_pkthdr *pkt_header, const u_char *pkt_data):
#     """
#     捕获数据包回调函数
#     """

#     if user != NULL:
#         pcap_dump(user, pkt_header, pkt_data)


def sniff(str iface, str filters="", int count=-1, str out_file=""):
    """
    捕获数据包

    :param iface: 网卡
    :param filters: BPF过滤规则, 默认 `""`
    :param count: 捕获数据包数量, 默认 `-1`
    :param out_file: 输出文件，默认 `""`
    """

    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef pcap_pkthdr pkt_header
    cdef pcap_dumper_t *out_pcap = NULL
    cdef pcap_t* handler = pcap_open_live(iface.encode("utf-8"), BUFSIZ, 1, 0, errbuf)

    if handler == NULL:
        raise ValueError(errbuf.decode("utf-8"))

    if out_file:
        out_pcap = pcap_dump_open(handler, out_file.encode("utf-8"))

    if filters:
        set_filter(handler, filters.encode("utf-8"))

    # pcap_loop(handler, count, sniff_callback, <u_char*>out_pcap)

    while count == -1 or count > 0:

        pkt = <u_char*>pcap_next(handler, &pkt_header)

        if out_pcap != NULL:
            pcap_dump(<u_char*>out_pcap, &pkt_header, pkt)

        yield pkt_header.caplen, pkt_header.ts.tv_sec, (<char*>pkt)[:pkt_header.caplen]

        if count > 0:
            count -= 1

    if out_pcap != NULL:
        pcap_dump_flush(out_pcap)
        pcap_dump_close(out_pcap)

    pcap_close(handler)
