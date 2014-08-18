#!/usr/bin/env python
from sys import platform
from sslyze import PROJECT_VERSION, PROJECT_URL, PROJECT_EMAIL, PROJECT_DESC
from distutils.core import setup


NASSL_BINARY = '_nassl.so'
if platform == 'win32':
    NASSL_BINARY = '_nassl.pyd'


SSLYZE_SETUP = {
    'name' : 'SSLyze',
    'version' : PROJECT_VERSION,
    'description' : PROJECT_DESC,
    'long_description' : open('README.md').read() + '\n' + open('AUTHORS.txt').read(),
    'author_email' : PROJECT_EMAIL,
    'url' : PROJECT_URL,
    'scripts' : ['sslyze.py'],
    'packages' : ['plugins', 'utils', 'nassl'],
    'package_data' : {'plugins' : ['data/trust_stores/*.pem','data/trust_stores/mozilla_ev_oids.py'],
                     'nassl' : [NASSL_BINARY]},
    'license' : open('LICENSE.txt').read()
}

setup(**SSLYZE_SETUP)