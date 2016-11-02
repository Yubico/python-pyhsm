# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


from setuptools import setup, find_packages
import re

VERSION_PATTERN = re.compile(r"(?m)^__version__\s*=\s*['\"](.+)['\"]$")


def get_version():
    """Return the current version as defined by yubico/yubico_version.py."""

    with open('pyhsm/__init__.py', 'r') as f:
        match = VERSION_PATTERN.search(f.read())
        return match.group(1)

setup(
    name='pyhsm',
    version=get_version(),
    description='Python code for talking to a YubiHSM',
    author='Dain Nilsson',
    author_email='dain@yubico.com',
    url='https://github.com/Yubico/python-pyhsm',
    license='BSD 2 clause',
    packages=find_packages(exclude=['test']),
    entry_points={
        'console_scripts': [
            # tools
            'yhsm-daemon = pyhsm.stick_daemon:main [daemon]',
            'yhsm-decrypt-aead = pyhsm.tools.decrypt_aead:main',
            'yhsm-generate-keys = pyhsm.tools.generate_keys:main',
            'yhsm-keystore-unlock = pyhsm.tools.keystore_unlock:main',
            'yhsm-linux-add-entropy = pyhsm.tools.linux_add_entropy:main',
            # ksm
            'yhsm-yubikey-ksm = pyhsm.ksm.yubikey_ksm:main [db,daemon]',
            'yhsm-import-keys = pyhsm.ksm.import_keys:main',
            'yhsm-db-export = pyhsm.ksm.db_export:main [db]',
            'yhsm-db-import = pyhsm.ksm.db_import:main [db]',
            # validation server
            'yhsm-validation-server = pyhsm.val.validation_server:main',
            'yhsm-validate-otp = pyhsm.val.validate_otp:main',
            'yhsm-init-oath-token = pyhsm.val.init_oath_token:main'
        ]
    },
    test_suite='test.test_init',
    tests_require=[],
    install_requires=[
        'pyserial >= 2.3',
        'pycrypto >= 2.1'
    ],
    extras_require={
        'db': ['sqlalchemy>=0.9.7'],
        'daemon': ['python-daemon']
    },
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
    ]
)
