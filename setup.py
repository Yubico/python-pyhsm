#!/usr/bin/env python

from setuptools import setup, find_packages
from distutils import versionpredicate

import sys
sys.path.append('Tests');

requires = [
    'pyserial >= 2.3',
    'pycrypto >= 2.1',
    'python-daemon >= 1.5'
]

setup(name		= 'pyhsm',
      version		= '1.0.4h',
      description	= 'Python code for talking to a YubiHSM',
      author		= 'Fredrik Thulin',
      author_email	= 'fredrik@yubico.com',
      url		= 'http://www.yubico.com/',
      license		= 'BSD',
      packages		= ['pyhsm'],
      package_dir	= {'': 'Lib'},
      test_suite	= "test_init.suite",
      install_requires	= requires,
      build_requires	= requires,
     )
