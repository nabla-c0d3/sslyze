# Only tested on Windows with Python 3.6 32 bits
# D:\Python36-32\python.exe setup_cx_freeze.py build_exe

import os
from cx_Freeze import setup, Executable
from setup import SSLYZE_SETUP

# Add lib to the path
import sys
sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'lib'))

# Trust Stores
plugin_data_files = []
trust_stores_pem_path = os.path.join('sslyze', 'plugins', 'utils', 'trust_store', 'pem_files')
for file in os.listdir(trust_stores_pem_path):
    file = os.path.join(trust_stores_pem_path, file)
    if os.path.isfile(file):  # skip directories
        filename = os.path.basename(file)
        plugin_data_files.append((file, os.path.join('pem_files', filename)))

sslyze_setup_py2exe = SSLYZE_SETUP.copy()

build_exe_options = {"packages": ['cffi', 'cryptography', 'idna'],
                     'include_files': plugin_data_files,}

sslyze_setup_py2exe.update({
    'options':  {"build_exe": build_exe_options},
    'executables': [Executable(os.path.join('sslyze', '__main__.py'))],
    })

if __name__ == "__main__":
    setup(**sslyze_setup_py2exe)
