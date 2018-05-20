from pathlib import Path
from sys import platform

from invoke import task


@task
def test(ctx):
    ctx.run('pytest')
    ctx.run('flake8 sslyze')
    ctx.run('mypy sslyze')

@task
def gen_doc(ctx):
    docs_folder_path = Path(__file__).parent / 'docs'
    dst_path = docs_folder_path / 'documentation'
    ctx.run(f'python -m sphinx -v -b html {docs_folder_path} {dst_path}')


@task
def release(ctx):
    pass

@task
def build_exe(ctx):
    if platform != 'win32':
        raise EnvironmentError('Can only be used on Windows')
    ctx.run('python setup.py build_exe')
