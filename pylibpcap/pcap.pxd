# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-05-10 11:19:43
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-03 10:30:47


ctypedef unsigned int u_int
ctypedef unsigned char u_char


cdef extern from "stdio.h":

    ctypedef struct FILE:
        pass


cdef extern from "pcap.h" nogil:

    ctypedef int bpf_int32

    ctypedef u_int bpf_u_int32

    struct bpf_insn:
        int __xxx

    struct bpf_program:
        bpf_insn *bf_insns

    struct bpf_timeval:
        u_int tv_sec
        u_int tv_usec

    struct pcap_stat:
        u_int ps_recv  # 在网络上传输的数据包数
        u_int ps_drop  # 驱动程序丢弃的数据包数
        u_int ps_ifdrop  # 按界面删除，尚不支持

        # 特定于Win32。捕获的数据包数，即过滤器接受的数据包数,
        # 它们位于内核缓冲区中，因此实际到达应用程序。为了向后兼容,
        # pcap_stats（）不会填充此成员，因此请使用pcap_stats_ex（）来获取它。
        u_int ps_capt
        u_int ps_sent
        u_int ps_netdrop

    struct pcap_pkthdr:
        bpf_timeval ts  # 时间戳
        bpf_u_int32 caplen  # 存在的部分长度
        bpf_u_int32 len  # 这个包的长度

    # struct pcap_addr:
    #     pcap_addr *next
    #     sockaddr *addr
    #     sockaddr *netmask
    #     sockaddr *broadaddr
    #     sockaddr *dstaddr

    ctypedef struct pcap_t:
        pass

    ctypedef struct pcap_dumper_t:
        pass

    ctypedef struct pcap_if_t:
        pass

    ctypedef struct pcap_addr_t:
        pass


# 接收数据包的回调函数的原型
ctypedef void (*pcap_handler)(u_char *, const pcap_pkthdr *, const u_char *)


cdef extern from "pcap.h":

    # 在网络中打开一个活动的捕获
    pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                           int to_ms, char *ebuf)

    # 在还没开始捕获时，创建一个pcap_t的结构体
    pcap_t *pcap_open_dead(int linktype, int snaplen)

    # 打开一个 tcpdump/libpcap 格式的存储文件，来读取数据包
    pcap_t *pcap_open_offline(const char *fname, char *errbuf)

    # 打开一个文件来写入数据包
    pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)

    # 阻塞和非阻塞模式之间切换
    int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)

    # 获得一个接口的非阻塞状态信息
    int pcap_getnonblock(pcap_t *p, char* errbuf)

    # 构造一个可打开的网络设备的列表
    int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)

    # 释放一个接口列表，这个列表将被pcap_findalldevs()返回
    void pcap_freealldevs(pcap_if_t *alldevs)

    # 返回系统中第一个合法的设备
    char *pcap_lookupdev(char *errbuf)

    # 返回接口的子网和掩码
    int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)

    # 收集一组数据包
    int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)

    # 收集一组数据包
    int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)

    # 返回下一个可用的数据包
    u_char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)

    # 从一个设备接口，或从一个脱机文件中，读取一个数据包
    int pcap_next_ex(pcap_t *p, pcap_pkthdr **pkt_header, const u_char **pkt_data)

    # 设置一个标志位，这个标志位会强制pcap_dispatch()或pcap_loop()返回，而不是继续循环
    void pcap_breakloop(pcap_t *)

    # 发送一个原始数据包
    int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)

    int pcap_inject(pcap_t *p, const void *buf, size_t size)

    # 将数据包保存到磁盘
    void pcap_dump(u_char *user, const pcap_pkthdr *h, const u_char *sp)

    # 返回存储文件的文件位置
    long pcap_dump_ftell(pcap_dumper_t *)

    # 编译数据包过滤器，将程序中高级的过滤表达式，转换成能被内核级的过滤引擎所处理的东西
    int pcap_compile(pcap_t *p, bpf_program *fp, char *str, int optimize,
                     bpf_u_int32 netmask)

    # 在不需要打开适配器的情况下，编译数据包过滤器。这个函数能将程序中高级的过滤表达式，转换成能被内核级的过滤引擎所处理的东西
    int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, bpf_program *program,
                            char *buf, int optimize, bpf_u_int32 mask)

    # 在捕获过程中绑定一个过滤器
    int pcap_setfilter(pcap_t *p, bpf_program *fp)

    # 释放一个过滤器
    void pcap_freecode(bpf_program *fp)

    # 返回适配器的链路层
    int pcap_datalink(pcap_t *p)

    # 列出数据链
    int pcap_list_datalink(pcap_t *p, int **dlt_buf)

    # 将当前pcap描述符的数据链的类型，设置成dlt给出的类型。返回-1表示设置失败
    int pcap_set_datalink(pcap_t *p, int dlt)

    # 转换一个数据链类型的名字，即将具有DLT_remove的DLT_name，转换成符合数据链类型的值。转换是区分大小写的，返回-1表示错误。
    int pcap_datalink_name_to_val(const char *name)

    # 将数据链类型值转换成合适的数据链类型的名字。返回NULL表示转换失败。
    const char *pcap_datalink_val_to_name(int dlt)

    # 将数据链类型值转换成合适的数据链类型的简短的名字。返回NULL表示转换失败。
    const char *pcap_datalink_val_to_description(int dlt)

    # 返回发送给应用程序的数据包部分的大小(字节)
    int pcap_snapshot(pcap_t *p)

    # 当前存储文件使用与当前系统不同的字节序列时，返回true
    int pcap_is_swapped(pcap_t *p)

    # 返回正在用来写入存储文件的pcap库的主要版本号
    int pcap_major_version(pcap_t *p)

    # 返回正在用来写入存储文件的pcap库的次要版本号
    int pcap_minor_version(pcap_t *p)

    # 返回一个脱机捕获文件的标准流
    FILE *pcap_file(pcap_t *p)

    # 返回当前捕获的统计信息
    int pcap_stats(pcap_t *p, pcap_stat *ps)

    # 在标准错误输出台打印最后一次pcap库错误的文本信息，前缀是prefix
    void pcap_perror(pcap_t *p, char *prefix)

    # 返回最后一次pcap库错误的文本信息
    char *pcap_geterr(pcap_t *p)

    # 提供这个函数，以防 strerror() 不能使用。
    char *pcap_strerror(int error)

    # 返回一个字符串，这个字符串保存着libpcap库的版本信息。注意，它除了版本号，还包含了更多的信息。
    const char *pcap_lib_version()

    # 关闭一个和p关联的文件，并释放资源
    void pcap_close(pcap_t *p)

    # 返回一个由 pcap_dump_open()打开的存储文件的标准输入输出流
    FILE *pcap_dump_file(pcap_dumper_t *p)

    # 将输出缓冲写入存储文件，这样，任何使用pcap_dump()存储，但还没有写入文件的数据包，会被立刻写入文件。
    # 返回-1表示出错，返回0表示成功。
    int pcap_dump_flush(pcap_dumper_t *p)

    # 关闭一个存储文件
    void pcap_dump_close(pcap_dumper_t *p)

    # Windows平台专用的扩展函数

    # 阻塞，直到网络连接建立。(仅用于激活模式)
    # SOCKET pcap_remoteact_accept(const char *address, const char *port, const char *hostlist,
    #                              char *connectinghost, pcap_rmtauth *auth, char *errbuf)

    # 释放一个活动连接 (仅用于激活模式).
    int pcap_remoteact_close(const char *host, char *errbuf)

    # 清除一个正在用来等待活动连接的socket
    void pcap_remoteact_cleanup()

    # 返回一个主机名，这个主机和我们建立了活动连接。(仅用于激活模式)
    int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf)

    pcap_t *pcap_create(char *source, char *errbuf)

    int pcap_set_snaplen(pcap_t *p, int snaplen)

    int pcap_set_promisc(pcap_t *p, int promisc)

    int pcap_set_timeout(pcap_t *p, int to_ms)

    int pcap_set_immediate_mode(pcap_t *p, int immediate_mode)

    int pcap_set_rfmon(pcap_t *p, int rfmon)

    int pcap_activate(pcap_t *p)

    int bpf_filter(bpf_insn *insns, const u_char *buf, u_int len, u_int caplen)

    pcap_t *pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision)
