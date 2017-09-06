#!/usr/bin/env python
from sslyze import PROJECT_URL, PROJECT_DESC, __author__, __email__, __version__, __license__


SSLYZE_SETUP = {
    'name': 'SSLyze',
    'version': __version__,
    'description': PROJECT_DESC,
    'author': __author__,
    'author_email': __email__,
    'license': __license__,
    'url': PROJECT_URL,
    'entry_points': {'console_scripts': ['sslyze = sslyze.__main__:main']},
    'packages': ['sslyze', 'sslyze.cli', 'sslyze.utils', 'sslyze.plugins', 'sslyze.plugins.utils',
                 'sslyze.plugins.utils.trust_store'],
    'package_data': {'sslyze.plugins.utils.trust_store': ['pem_files/*.pem']},
    'install_requires': ['nassl>=0.17.0,<0.18.0',
                         'cryptography==1.9',
                         'tls-parser==1.1.0'],
    'extras_require': {':python_version < "3.4"': ['enum34'],
                       ':python_version < "3.5"': ['typing']},
    'classifiers': [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: French',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: System :: Networking',
        'Topic :: Security'
    ],
}

if __name__ == "__main__":
    # Importing setuptools here because setup_py2exe also imports SSLYZE_SETUP but needs to use distutils
    from setuptools import setup

    setup(**SSLYZE_SETUP)
