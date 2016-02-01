#!/usr/bin/env python2.7
from sslyze import PROJECT_URL, PROJECT_DESC, __author__, __email__, __version__, __license__
from setuptools import setup


SSLYZE_SETUP = {
    'name': 'SSLyze',
    'version': __version__,
    'description': PROJECT_DESC,
    'author': __author__,
    'author_email': __email__,
    'license': __license__,
    'url': PROJECT_URL,
    'scripts': ['sslyze_cli.py'],
    'packages': ['sslyze', 'sslyze.plugins', 'sslyze.utils'],
    'package_data': {'sslyze.plugins': ['data/trust_stores/*.pem']},
    'install_requires': ['nassl>=0.13.0,<1.14.0'],
    'classifiers': [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: French',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
        'Topic :: Security'
    ],
}

if __name__ == "__main__":
    setup(**SSLYZE_SETUP)
