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
trust_stores_pem_path = os.path.join('sslyze', 'plugins', 'utils', 'trust_store', 'pem_files')
for file in os.listdir(trust_stores_pem_path):
    file = os.path.join(trust_stores_pem_path, file)
    if os.path.isfile(file):  # skip directories
        plugin_data_files.append(file)

data_files.append((os.path.join('utils', 'trust_store', 'pem_files'), plugin_data_files))

sslyze_setup_py2exe = SSLYZE_SETUP.copy()
# Add nassl to the list of packages
sslyze_setup_py2exe['packages'].append('nassl')
sslyze_setup_py2exe.update(
        {
            # Force the packaging of the C extension
            'package_data': {'nassl': ['_nassl.pyd']},
            'console': ['sslyze\\__main__.py'],
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
