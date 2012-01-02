#!/usr/bin/env python

from distutils.core import setup
from setuptools import setup, find_packages

import sys
sys.path.append('Tests');

setup(name		= 'pyhsm',
      version		= '1.0.3b',
      description	= 'Python code for talking to a YubiHSM',
      author		= 'Fredrik Thulin',
      author_email	= 'fredrik@yubico.com',
      url		= 'http://www.yubico.com/',
      license		= 'BSD',
      packages		= ['pyhsm'],
      package_dir	= {'': 'Lib'},
      test_suite	= "test_init.suite"
     )
