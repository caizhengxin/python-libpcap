# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 23:19:03
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-12 12:45:02
import os


def to_c_str(v):
    """
    Python str to C str
    """

    return v.encode("utf-8")


def from_c_str(v):
    """
    C str to Python str
    """

    return v.decode("utf-8")


def get_pcap_file(path):
    """
    get pcap file

    :param path: path.
    """

    if isinstance(path, bytes):
        path = from_c_str(path)

    return (
        os.path.join(directory, file)
        for directory, dirs, files in os.walk(path)
        for file in files if ".pcap" in file
    )
