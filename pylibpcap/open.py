# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-09-11 17:43:19
# @Last Modified by:   caizhengxin@bolean.com.cn
# @Last Modified time: 2019-09-12 09:27:39
from pylibpcap.base import BasePcap


class OpenPcap(object):
    """
    OpenPcap
    """

    def __init__(self, path, mode="r", *args, **kwargs):
        """
        init

        :param path: file path.
        :param mode: file model, default ``r``
        """

        self.mode = mode
        self.path = path
        self.pcapobj = BasePcap(path, *args, **kwargs)

    def read(self):
        """
        Read
        """

        return self.pcapobj.read()

    def write(self, v):
        """
        Write

        :param v: Payload
        """

        return self.pcapobj.write(v)

    def __enter__(self):
        """
        enter
        """

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        exit
        """

        self.pcapobj.close()
