#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
from subprocess import Popen, PIPE
import shutil

docs_folder_path = os.path.abspath(os.path.dirname(__file__))
p1 = Popen('python -m sphinx -v -b html {src} {dst}'.format(
    src=docs_folder_path, dst=os.path.join(docs_folder_path, '_build')
), shell=True, stdin=PIPE, stdout=PIPE)

result = p1.communicate()[0].decode('utf-8')
if not result or 'build succeeded' not in result:
    raise RuntimeError('sphinx-build failed')

final_folder_path = os.path.join(docs_folder_path, 'documentation')
if os.path.isdir(final_folder_path):
    shutil.rmtree(final_folder_path)
shutil.copytree(os.path.join(docs_folder_path, '_build') , final_folder_path)
