# -*- coding: utf-8 -*-
# @Author: JanKinCai
# @Date:   2019-11-09 10:08:53
# @Last Modified by:   JanKinCai
# @Last Modified time: 2020-07-07 09:35:38
import os
import glob

from setuptools import setup, find_packages
from setuptools import Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext


with open('README.rst') as f:
    long_description = f.read()


def read_requirements(path):
    """
    递归读取requirements

    :param path: path
    """

    requires = []

    with open(path) as f:
        install_requires = f.read().split("\n")

        for ir in install_requires:
            if "-r" in ir:
                path = os.path.join(os.path.split(path)[0], ir.split(" ")[1])
                requires.extend(read_requirements(path))
            else:
                ir and requires.append(ir)

    return requires


# local or publish
USE_CYTHON = True if glob.glob("pylibpcap/*.pyx") else False
ext = '.pyx' if USE_CYTHON else '.c'

ext_modules = [
    Extension(
        "{}/{}".format(directory, file.split(".")[0]).replace("/", "."),
        sources=["{}/{}".format(directory, file)],
        libraries=["m"],
        # include_dirs=["src"],
        extra_compile_args=["-lpcap"],
        extra_link_args=["-lpcap"],
    )
    for directory, dirs, files in os.walk("pylibpcap")
    for file in files if ext in file and ".pyc" not in file
]

ext_modules = cythonize(ext_modules) if USE_CYTHON else ext_modules


setup(
    name="python-libpcap",
    version="0.2.5",
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
        "libpcap-python",
    ],
    zip_safe=False,
    packages=find_packages(),
    cmdclass={
        "build_ext": build_ext
    },
    ext_modules=ext_modules,
    install_requires=read_requirements("requirements/publish.txt"),
    entry_points={
        "console_scripts": [
            "mpcap = pylibpcap.command:main",
            "capture = pylibpcap.command:pylibpcap_sniff",
            "wpcap = pylibpcap.command:write_pcap_cli",
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries'
    ],
)
