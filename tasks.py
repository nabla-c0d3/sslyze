from pathlib import Path
from sys import platform

# Monkeypatch for Python 3.11
# TODO: Remove after this is fixed: https://github.com/pyinvoke/invoke/issues/833
import inspect

if not hasattr(inspect, "getargspec"):
    inspect.getargspec = inspect.getfullargspec  # type: ignore


from invoke import task, Context
from sslyze import __version__

root_path = Path(__file__).parent.absolute()


@task
def test(ctx):
    # type: (Context) -> None
    ctx.run("pytest --cov=sslyze --cov-fail-under 80 --durations 5")


@task
def lint(ctx):
    # type: (Context) -> None
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
    # WARNING(AD): This does not work well within a pipenv and the system's Python should be used
    ctx.run("python setup.py build_exe")


@task
def gen_json_schema(ctx):
    # type: (Context) -> None
    from sslyze.json.json_output import SslyzeOutputAsJson

    json_schema = SslyzeOutputAsJson.schema_json(indent=2)
    json_schema_file = Path(__file__).parent / "json_output_schema.json"
    json_schema_file.write_text(json_schema)
