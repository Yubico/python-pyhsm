#!/usr/bin/env python

from distutils.core import setup
from setuptools import setup, find_packages

import sys
sys.path.append('Tests');

setup(name		= 'python-serveronstick',
      version		= '0.9.0pre1',
      description	= 'Python code for talking to a YubiHSM',
      author		= 'Fredrik Thulin',
      author_email	= 'fredrik@yubico.com',
      url		= 'http://www.yubico.com/',
      license		= 'BSD',
      packages		= ['serveronstick'],
      package_dir	= {'': 'Lib'},
      #tests_require	= "nose >=0.10.0b1",
      #test_suite	= "nose.collector",
      test_suite	= "test_init.suite"
     )
