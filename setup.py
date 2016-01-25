#!/usr/bin/env python2.7
from sslyze import PROJECT_URL, PROJECT_DESC, __author__, __email__, __version__, __license__
from distutils.core import setup


SSLYZE_SETUP = {
    'name': 'SSLyze',
    'version': __version__,
    'description': PROJECT_DESC,
    'long_description': open('README.md').read(),
    'author': __author__,
    'author_email': __email__,
    'license': __license__,
    'url': PROJECT_URL,
    'scripts': ['sslyze-cli.py'],
    'packages': ['sslyze', 'sslyze.plugins', 'sslyze.utils'],
    'package_data': {'sslyze.plugins': ['data/trust_stores/*.pem']},
    'install_requires': ['nassl']
}

setup(**SSLYZE_SETUP)
