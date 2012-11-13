#!/usr/bin/env python

from sslyze import SSLYZE_VERSION, PROJECT_URL
from distutils.core import setup

setup(name='SSLyze',
    version=SSLYZE_VERSION,
    description='Fast and full-featured SSL scanner',
    long_description=open('README.md').read()+ '\n' +
                     open('AUTHORS.txt').read(),
    author_email='sslyze@isecpartners.com',
    url=PROJECT_URL,
    scripts=['sslyze.py'],
    packages=['plugins', 'utils', 'utils.ctSSL'],
    package_data={'plugins': ['data/mozilla_cacert.pem','data/mozilla_ev_oids.py']},
    license=open('LICENSE.txt').read(),
    )
