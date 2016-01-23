#!/usr/bin/env python2.7
from sslyze import PROJECT_VERSION, PROJECT_URL, PROJECT_EMAIL, PROJECT_DESC
from distutils.core import setup


SSLYZE_SETUP = {
    'name': 'SSLyze',
    'version': PROJECT_VERSION,
    'description': PROJECT_DESC,
    'long_description': open('README.md').read() + '\n' + open('AUTHORS.txt').read(),
    'author_email': PROJECT_EMAIL,
    'url': PROJECT_URL,
    'scripts': ['sslyze-cli.py'],
    'packages': ['sslyze', 'sslyze.plugins', 'sslyze.utils'],
    'package_data': {'sslyze.plugins': ['data/trust_stores/*.pem']},
    'license': open('LICENSE.txt').read()
}

setup(**SSLYZE_SETUP)
