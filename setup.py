#!/usr/bin/env python

from distutils.core import setup as distutils_setup
from os import walk, getcwd
from os.path import join as path_join
from shutil import move
from subprocess import Popen, PIPE
from sys import argv, platform
from tarfile import open as tarfile_open
from urllib import urlretrieve


def setup():
    if 'egg_info' in argv:
        temp_dir = getcwd()
        zlib_arch = 'zlib-1.2.8.tar.gz'
        openssl_arch = 'openssl-1.0.2a.tar.gz'
        nassl_dir = '{}/nassl.downloaded'.format(temp_dir)
        nassl_build_dir = ''

        try:
            Popen(['git', 'clone', 'https://github.com/ZenSecurity/nassl.git', nassl_dir]).wait()
            urlretrieve('http://zlib.net/{}'.format(zlib_arch), '{}/{}'.format(nassl_dir, zlib_arch))
            tarfile_open('{}/{}'.format(nassl_dir, zlib_arch)).extractall(nassl_dir)
            urlretrieve('http://www.openssl.org/source/old/1.0.2/{}'.format(openssl_arch), '{}/{}'.format(nassl_dir, openssl_arch))
            tarfile_open('{}/{}'.format(nassl_dir, openssl_arch)).extractall(nassl_dir)
            Popen(['python', 'buildAll_unix.py'], cwd=nassl_dir).wait()

            for root, dirs, files in walk('{}/build'.format(nassl_dir)):
                if 'nassl' in dirs:
                    nassl_build_dir = path_join(root, 'nassl')

            move(nassl_build_dir, "{}/nassl".format(temp_dir))
        except Exception as exception:
            print('{} - {}'.format(exception.__class__.__name__, exception))

    NASSL_BINARY = '_nassl.so'
    if platform == 'win32':
            NASSL_BINARY = '_nassl.pyd'

    from sslyze import PROJECT_VERSION, PROJECT_URL, PROJECT_EMAIL, PROJECT_DESC

    distutils_setup(
        name='SSLyze',
        version=PROJECT_VERSION,
        description=PROJECT_DESC,
        long_description=open('README.md').read() + '\n' + open('AUTHORS.txt').read(),
        author_email=PROJECT_EMAIL,
        url=PROJECT_URL,
        scripts=['sslyze.py'],
        packages=['plugins', 'utils', 'nassl'],
        package_data=dict(plugins=['data/trust_stores/*.pem'], nassl=[NASSL_BINARY]),
        license=open('LICENSE.txt').read()
    )

setup()
