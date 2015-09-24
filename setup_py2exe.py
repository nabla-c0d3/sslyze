#!/usr/bin/env python
# C:\Python27_32\python.exe setup_py2exe.py py2exe
from distutils.core import setup
from glob import glob

import os
import py2exe
from setup import SSLYZE_SETUP


data_files = [("Microsoft.VC90.CRT", glob(r'C:\Program Files\Microsoft Visual Studio 9.0\VC\redist\x86\Microsoft.VC90.CRT\*.*'))]

# Trust Stores
plugin_data_files = []
for file in os.listdir('plugins\\data\\trust_stores'):
    file = os.path.join('plugins\\data\\trust_stores', file)
    if os.path.isfile(file): # skip directories
        plugin_data_files.append( file)

data_files.append(('data\\trust_stores', plugin_data_files))


sslyze_setup_py2exe = SSLYZE_SETUP.copy()
sslyze_setup_py2exe.update(
    {
        'console' : ['sslyze.py'],
        'data_files' : data_files,
        'zipfile' : None,
        'options' : {'py2exe':{
            #'skip_archive': True,
            'bundle_files': 1,
            }}

    }
)

setup(**sslyze_setup_py2exe)
