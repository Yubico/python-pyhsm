#!/usr/bin/env python

from setuptools import setup, find_packages
from distutils import versionpredicate

import sys
sys.path.append('Tests');

setup(name		= 'pyhsm',
      version		= '1.0.4l',
      description	= 'Python code for talking to a YubiHSM',
      author		= 'Fredrik Thulin',
      author_email	= 'fredrik@yubico.com',
      url		= 'https://www.yubico.com/',
      license		= 'BSD',
      packages		= ['pyhsm'],
      package_dir	= {'': 'Lib'},
      test_suite	= "test_init.suite",
      install_requires	= ['pyserial >= 2.3',
                           'pycrypto >= 2.1',
                           'python-daemon >= 1.5',
                           'sqlalchemy >= 0.9.7'],
  )
