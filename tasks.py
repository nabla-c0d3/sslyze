from pathlib import Path
from sys import platform

from invoke import task, Context
from sslyze import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # type: (Context) -> None
    # Run the test suite
    ctx.run("pytest --cov=sslyze --cov-fail-under 80")

    # Run linters
    ctx.run("flake8 .")
    ctx.run("mypy .")
    ctx.run("black -l 120 sslyze tests api_sample.py tasks.py --check")


@task
def gen_doc(ctx):
    # type: (Context) -> None
    docs_folder_path = root_path / "docs"
    dst_path = docs_folder_path / "documentation"
    ctx.run(f"python -m sphinx -v -b html {docs_folder_path} {dst_path}")


@task
def release(ctx):
    # type: (Context) -> None
    response = input(f'Release version "{__version__}" ? y/n')
    if response.lower() != "y":
        print("Cancelled")
        return

    # Ensure the tests pass
    test(ctx)

    # Ensure the API samples work
    ctx.run("python api_sample.py")

    # Add the git tag
    ctx.run(f"git tag -a {__version__} -m '{__version__}'")
    ctx.run("git push --tags")

    # Generate the doc
    gen_doc(ctx)

    # Upload to Pypi
    ctx.run("python setup.py sdist")
    sdist_path = root_path / "dist" / f"sslyze-{__version__}.tar.gz"
    ctx.run(f"twine upload {sdist_path}")


@task
def build_exe(ctx):
    # type: (Context) -> None
    if platform != "win32":
        raise EnvironmentError("Can only be used on Windows")
    # WARNING(AD): The resulting executable does not work (_ssl ImportError) if it was built using Python 3.7
    ctx.run("python setup.py build_exe")
