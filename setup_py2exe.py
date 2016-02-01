#!/usr/bin/env python2.7
# C:\Python27_32\python.exe setup_py2exe.py py2exe
from distutils.core import setup
from glob import glob

import os
import py2exe
from setup import SSLYZE_SETUP

data_files = [
    ("Microsoft.VC90.CRT", glob(r'C:\Program Files\Microsoft Visual Studio 9.0\VC\redist\x86\Microsoft.VC90.CRT\*.*'))]

# Trust Stores
plugin_data_files = []
for file in os.listdir('sslyze\\plugins\\data\\trust_stores'):
    file = os.path.join('sslyze\\plugins\\data\\trust_stores', file)
    if os.path.isfile(file):  # skip directories
        plugin_data_files.append(file)

data_files.append(('data\\trust_stores', plugin_data_files))

sslyze_setup_py2exe = SSLYZE_SETUP.copy()
sslyze_setup_py2exe.update(
        {
            # Add nassl to the list of packages
            'packages': ['sslyze', 'sslyze.plugins', 'sslyze.utils', 'nassl',],
            # Force the packaging of the C extension
            'package_data': {'nassl': ['_nassl.pyd']},
            'console': ['sslyze_cli.py'],
            'data_files': data_files,
            'zipfile': None,
            'options': {'py2exe': {
                # 'skip_archive': True,
                'bundle_files': 1,
            }}

        }
)

if __name__ == "__main__":
    setup(**sslyze_setup_py2exe)
