# -*- coding: utf-8 -*-
#!/usr/bin/python

import os
from subprocess import Popen, PIPE
import shutil

docs_folder_path = os.path.join(os.path.dirname(__file__))
p1 = Popen(u'sphinx-build -M html {src} {dst}'.format(
    src=docs_folder_path, dst=os.path.join(docs_folder_path, u'_build')
), shell=True, stdin=PIPE, stdout=PIPE)

result = p1.communicate()[0]
if not result or u'build succeeded' not in result:
    raise RuntimeError(u'sphinx-build failed')

final_folder_path = os.path.join(docs_folder_path, u'documentation')
shutil.rmtree(final_folder_path)
shutil.copytree(os.path.join(docs_folder_path, u'_build', u'html') , final_folder_path)
