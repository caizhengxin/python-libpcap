==============
python-libpcap
==============

.. image:: https://img.shields.io/pypi/v/python-libpcap.svg
        :target: https://pypi.python.org/pypi/python-libpcap

.. image:: https://img.shields.io/pypi/pyversions/python-libpcap.svg
        :target: https://pypi/python.org/pypi/python-libpcap

.. image:: https://api.travis-ci.com/caizhengxin/python-libpcap.svg?branch=master
        :target: https://travis-ci.org/JanKinCai/python-libpcap

.. image:: https://img.shields.io/pypi/dm/python-libpcap.svg
        :target: https://pypi/python.org/pypi/python-libpcap

.. image:: https://readthedocs.org/projects/python-libpcap/badge/?version=latest
        :target: https://python-libpcap.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://img.shields.io/github/languages/code-size/caizhengxin/python-libpcap
        :target: https://github.com/caizhengxin/python-libpcap

.. image:: https://img.shields.io/pypi/l/python-libpcap
        :target: https://github.com/caizhengxin/python-libpcap/blob/master/LICENSE

Cython libpcap, read/write/merge/capture

* GIthub repo: https://github.com/caizhengxin/python-libpcap
* Documentation: https://python-libpcap.readthedocs.io
* Free software: BSD lincense

Features
--------

* Read pcap file
* Write pcap file
* Merge pcap file
* Multi-file quick merge
* Get first iface
* Get iface list
* Send raw packet
* Capture data

Installation
------------

To install python-libpcap, run this command in your terminal:

.. code-block:: console

    $ sudo apt-get install libpcap-dev
    $ pip3 install Cython
    $ pip3 install python-libpcap

Usage
-----

Command:

.. code-block:: console

    # Multi-file quick merge
    $ libpcap-merge -i test.pcap -o pcap.pcap port 502
    $ libpcap-merge -i pcap/ -o pcap.pcap port 502

    # Capture data packet
    $ sudo libpcap-capture -i enp0s3 -v -p port 22
    $ sudo libpcap-capture -i enp0s3 -o pcap.pcap port 22

    # Write packet
    $ libpcap-write --output pcap.pcap ac64175ffa41000ec6c9157e08004500004b8a1e400080060000c0a80002c0a80001c794006618e119b56ef0831d5018faf081910000030000231ee00000001d00c1020600c20f53494d415449432d524f4f542d4553c0010a

    # Read packet
    $ libpcap-read -i test.pcap -v -p port 502

Read pcap:

.. code-block:: python

    from pylibpcap.pcap import rpcap


    for len, t, pkt in rpcap("tests/dns.pcap"):
        print("Buf length:", len)
        print("Time:", t)
        print("Buf:", pkt)

Write pcap:

.. code-block:: python

    from pylibpcap import wpcap


    buf = b'\x00\xc0\x9f2A\x8c\x00\xe0\x18\xb1\x0c\xad\x08\x00E\x00\x008' \
          b'\x00\x00@\x00@\x11eG\xc0\xa8\xaa\x08\xc0\xa8\xaa\x14\x80\x1b' \
          b'\x005\x00$\x85\xed\x102\x01\x00\x00\x01\x00\x00\x00\x00\x00' \
          b'\x00\x06google\x03com\x00\x00\x10\x00\x01'


    wpcap(buf, "pcap.pcap")
    wpcap([buf, buf], "pcap.pcap)

.. code-block:: python

    from pylibpcap import OpenPcap


    with OpenPcap("pcap.pcap", "a") as f:
        f.write(buf)

Merge pcap:

.. code-block:: python

    from pylibpcap.pcap import mpcap


    mpcap("demo.pcap", "demo2.pcap")

    mpcap("pcap/", "output.pcap", "port 502")

Get first iface:

.. code-block:: python

    from pylibpcap import get_first_iface

    print(get_first_iface())

Get iface list:

.. code:: python

    from pylibpcap import get_iface_list

    print(get_iface_list())

Send raw packet:

.. code:: python

    from pylibpcap import send_packet

    send_packet("enp2s0", b"")

Capture data:

.. code-block:: python

    from pylibpcap.pcap import sniff


    for plen, t, buf in sniff("enp2s0", filters="port 53", count=-1, promisc=1, out_file="pcap.pcap"):
        print("[+]: Payload len=", plen)
        print("[+]: Time", t)
        print("[+]: Payload", buf)

.. code-block:: python

    from pylibpcap.base import Sniff


    sniffobj = Sniff("enp2s0", filters="port 53", count=-1, promisc=1, out_file="pcap.pcap")

    for plen, t, buf in sniffobj.capture():
        print("[+]: Payload len=", plen)
        print("[+]: Time", t)
        print("[+]: Payload", buf)

    stats = sniffobj.stats()
    print(stats.capture_cnt, " packets captured")
    print(stats.ps_recv, " packets received by filter")
    print(stats.ps_drop, "  packets dropped by kernel")
    print(stats.ps_ifdrop, "  packets dropped by iface")

Credits
-------

This package was created with Cookiecutter_ and the `caizhengxin/cookiecutter-package`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`caizhengxin/cookiecutter-package`: https://github.com/caizhengxin/cookiecutter-package
