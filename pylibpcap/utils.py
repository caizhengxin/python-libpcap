# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-04 23:19:03
# @Last Modified by:   jankincai12@gmail.com
# @Last Modified time: 2019-09-04 23:30:13
import os


def get_pcap_file(path):
    """
    获取pcap文件

    :param path: path.
    """

    return (
        os.path.join(directory, file)
        for directory, dirs, files in os.walk(path)
        for file in files if ".pcap" in file
    )


def to_c_name(file):
    """
    传给C程序的文件名

    :param file: 文件名
    """

    return file.encode("utf-8")
