# -*- coding: utf-8 -*-
import os

from setuptools import setup, find_packages
from setuptools import Extension

from Cython.Build import cythonize
from Cython.Distutils import build_ext


with open('README.rst') as f:
    long_description = f.read()

ext_modules = [
    Extension(
        "*",
        sources=["{}/{}".format(directory, file)],
        libraries=["m"],
        # include_dirs=["src"],
        extra_compile_args=["-lpcap"],
        extra_link_args=["-lpcap"],
    )
    for directory, dirs, files in os.walk("pylibpcap")
    for file in files if ".pyx" in file
]


setup(
    name="python-libpcap",
    version="0.1.3",
    author="JanKinCai",
    author_email="jankincai12@gmail.com",
    maintainer="JanKinCai",
    maintainer_email="jankincai12@gmail.com",
    url="https://github.com/caizhengxin/python-libpcap",
    download_url="https://github.com/caizhengxin/python-libpcap.git",
    license="BSD",
    description="Cython libpcap",
    long_description=long_description,
    keywords=[
        "python-libpcap",
        "pylibpcap",
        "libpcap",
        "pcap",
        "python",
        "linpcap-python",
    ],
    zip_safe=False,
    packages=find_packages(),
    cmdclass={
        "build_ext": build_ext
    },
    ext_modules=cythonize(ext_modules),
    install_requires=[
    ],
    entry_points={
        "console_scripts": [
            "mpcap = pylibpcap.command:main",
            "capture = pylibpcap.command:pylibpcap_sniff",
        ],
    },
    include_package_data=True,  # MANIFEST.in
    setup_requires=[
        "setuptools",
        "Cython",
    ],
    project_urls={
        "Documentation": "https://python-libpcap.readthedocs.io",
        "Source Code": "https://github.com/caizhengxin/python-libpcap",
    },
    platforms="Linux",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation',
        # 'Programming Language :: Python :: 2',
        # 'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries'
    ],
)
