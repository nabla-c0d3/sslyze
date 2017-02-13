#!/usr/bin/env python2.7
# C:\Python27_32\python.exe setup_py2exe.py py2exe
from distutils.core import setup
from glob import glob

import os
import py2exe
from setup import SSLYZE_SETUP

# Add lib to the path so py2exe can find the dependencies
import sys
sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'lib'))


data_files = [
    ("Microsoft.VC90.CRT", glob(r'C:\Program Files\Microsoft Visual Studio 9.0\VC\redist\x86\Microsoft.VC90.CRT\*.*'))]

# Trust Stores
plugin_data_files = []
trust_stores_pem_path = os.path.join('sslyze', 'plugins', 'utils', 'trust_store', 'pem_files')
for file in os.listdir(trust_stores_pem_path):
    file = os.path.join(trust_stores_pem_path, file)
    if os.path.isfile(file):  # skip directories
        plugin_data_files.append(file)

data_files.append((os.path.join('pem_files'), plugin_data_files))

sslyze_setup_py2exe = SSLYZE_SETUP.copy()

sslyze_setup_py2exe.update(
        {
            'console': [os.path.join('sslyze', '__main__.py')],
            # Add dependencies
            'include': ['nassl', 'typing', 'enum'],
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
