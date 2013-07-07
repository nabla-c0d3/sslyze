#!/usr/bin/env python

from sslyze import PROJECT_VERSION, PROJECT_URL, PROJECT_EMAIL, PROJECT_DESC
from distutils.core import setup

setup(name='SSLyze',
    version=PROJECT_VERSION,
    description=PROJECT_DESC,
    long_description=open('README.md').read() + '\n' +
                     open('AUTHORS.txt').read(),
    author_email=PROJECT_EMAIL,
    url=PROJECT_URL,
    scripts=['sslyze.py'],
    packages=['plugins', 'utils', 'nassl'],
    package_data={'plugins' : ['data/mozilla_cacert.pem','data/mozilla_ev_oids.py'],
                  'nassl' : ['_nassl.so']},
    license=open('LICENSE.txt').read(),
    )