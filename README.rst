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

* Documentation: https://python-libpcap.readthedocs.io.

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

    $ pylibpcap -i pcap/ -o pcap.pcap port 502

Read pcap:

.. include:: ../../demo/read_pcap.py

Write pcap:

.. include:: ../../demo/write_pcap.py

Merge pcap:

.. include:: ../../demo/merge_pcap.py

Get first iface:

.. code-block:: python

    from pylibpcap.pcap import get_first_iface

    print(get_first_iface())

Capture data:

.. include:: ../../demo/sniff.py


* TODO

Credits
-------

This package was created with Cookiecutter_ and the `caizhengxin/cookiecutter-package`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`caizhengxin/cookiecutter-package`: https://github.com/caizhengxin/cookiecutter-package
