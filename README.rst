==============
python-libpcap
==============

.. image:: https://img.shields.io/pypi/v/python-libpcap.svg
        :target: https://pypi.python.org/pypi/python-libpcap

.. image:: https://api.travis-ci.com/caizhengxin/python-libpcap.svg
        :target: https://travis-ci.org/JanKinCai/python-libpcap

.. image:: https://readthedocs.org/projects/python-libpcap/badge/?version=latest
        :target: https://python-libpcap.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

Cython libpcap

* Documentation: https://python-libpcap.readthedocs.io

Features
--------

* Read pcap file
* Write pcap file
* Merge pcap file
* Get first iface
* Capture data

Installation
------------

To install python-libpcap, run this command in your terminal:

.. code-block:: console

    $ sudo apt-get install libpcap-dev
    $ pip install python-libpcap

Demo
----

Console:

.. code-block:: console

    $ mpcap -i pcap/ -o pcap.pcap port 502
    $ sudo capture -i enp2s0 -v

Read pcap:

.. code-block:: python

    from pylibpcap.pcap import rpcap


    for len, t, pkt in rpcap("tests/dns.pcap"):
        print("Buf length：", len)
        print("Time：", t)
        print("Buf：", pkt)

Write pcap:

.. code-block:: python

    from pylibpcap.pcap import wpcap


    buf = b'\x00\xc0\x9f2A\x8c\x00\xe0\x18\xb1\x0c\xad\x08\x00E\x00\x008' \
          b'\x00\x00@\x00@\x11eG\xc0\xa8\xaa\x08\xc0\xa8\xaa\x14\x80\x1b' \
          b'\x005\x00$\x85\xed\x102\x01\x00\x00\x01\x00\x00\x00\x00\x00' \
          b'\x00\x06google\x03com\x00\x00\x10\x00\x01'


    wpcap(buf, "pcap.pcap")
    wpcap([buf, buf], "pcap.pcap)

Merge pcap:

.. code-block:: python

    from pylibpcap.pcap import mpcap


    mpcap("demo.pcap", "demo2.pcap")

    mpcap("pcap/", "output.pcap", "port 502")

Get first iface:

.. code-block:: python

    from pylibpcap.pcap import get_first_iface

    print(get_first_iface())

Capture data:

.. code-block:: python

    from pylibpcap.pcap import sniff


    for plen, t, buf in sniff("enp2s0", filters="port 53", count=3, promisc=1, out_file="pcap.pcap"):
        print("[+]: Payload len=", plen)
        print("[+]: Time", t)
        print("[+]: Payload", buf)

Credits
-------

This package was created with Cookiecutter_ and the `caizhengxin/cookiecutter-package`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`caizhengxin/cookiecutter-package`: https://github.com/caizhengxin/cookiecutter-package
