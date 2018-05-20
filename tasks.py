from pathlib import Path
from sys import platform

from invoke import task
from sslyze import __version__

root_path = Path(__file__).parent


@task
def test(ctx):
    # Run the test suite
    ctx.run('pytest')

    # Run linters
    ctx.run('flake8 sslyze')
    ctx.run('mypy sslyze')


@task
def gen_doc(ctx):
    docs_folder_path = root_path / 'docs'
    dst_path = docs_folder_path / 'documentation'
    ctx.run(f'python -m sphinx -v -b html {docs_folder_path} {dst_path}')


@task
def release(ctx):
    response = input(f'Release version "{__version__}" ? y/n')
    if response.lower() != 'y':
        print('Cancelled')
        return

    # Ensure the tests pass
    test(ctx)

    # Ensure the API samples work
    ctx.run('python api_sample.py')

    # Add the git tag
    ctx.run(f"git tag -a {__version__} -m '{__version__}'")
    ctx.run('git push --tags')

    # Upload to Pypi
    sdist_path = root_path / 'dist' / f'sslyze-{__version__}.tar.gz'
    ctx.run(f'twine upload {sdist_path}')


@task
def build_exe(ctx):
    if platform != 'win32':
        raise EnvironmentError('Can only be used on Windows')
    ctx.run('python setup.py build_exe')
