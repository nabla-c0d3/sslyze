import sys
from os import path, listdir
from pathlib import Path
from typing import List, Tuple, Dict

from setuptools import find_packages

# Setup file based on https://github.com/pypa/sampleproject/blob/master/setup.py
root_path = Path(__file__).parent.absolute()

# For cx_freeze builds, we need a special setup() function
if len(sys.argv) > 1 and sys.argv[1] == "build_exe":
    from cx_Freeze import setup
    from cx_Freeze import Executable
else:
    from setuptools import setup

    # Create fake Executable that does nothing so the setup.py file can be used on Linux
    class Executable:  # type: ignore
        def __init__(self, script, targetName):  # type: ignore
            pass


def get_long_description() -> str:
    path_to_readme = root_path / "README.md"
    return path_to_readme.read_text()


def get_project_info() -> Dict[str, str]:
    project_info: Dict[str, str] = {}
    project_info_path = root_path / "sslyze" / "__version__.py"
    exec(project_info_path.read_text(), project_info)
    return project_info


def get_include_files() -> List[Tuple[str, str]]:
    """"Get the list of trust stores so they properly packaged when doing a cx_freeze build.
    """
    plugin_data_files = []
    trust_stores_pem_path = root_path / "sslyze" / "plugins" / "certificate_info" / "trust_stores" / "pem_files"
    for file in listdir(trust_stores_pem_path):
        file = path.join(trust_stores_pem_path, file)
        if path.isfile(file):  # skip directories
            filename = path.basename(file)
            plugin_data_files.append((file, path.join("pem_files", filename)))
    return plugin_data_files


project_info = get_project_info()


setup(
    name=project_info["__title__"].lower(),
    version=project_info["__version__"],
    description=project_info["__description__"],
    url=project_info["__url__"],
    author=project_info["__author__"],
    author_email=project_info["__author_email__"],
    license=project_info["__license__"],
    python_requires=">=3.7",
    # Pypi metadata
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Natural Language :: French",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    keywords="ssl tls scan security library",
    project_urls={
        "Source": "https://github.com/nabla-c0d3/sslyze",
        "Changelog": "https://github.com/nabla-c0d3/sslyze/releases",
        "Documentation": "https://nabla-c0d3.github.io/sslyze/documentation",
    },
    # Package info
    packages=find_packages(exclude=["docs", "tests"]),
    package_data={
        "sslyze": ["py.typed"],
        "sslyze.plugins.certificate_info.trust_stores": ["pem_files/*.pem", "pem_files/*.yaml"],
    },
    entry_points={"console_scripts": ["sslyze = sslyze.__main__:main"]},
    # Dependencies
    install_requires=[
        "nassl>=3.0.0,<3.2.0",
        "cryptography==2.8",
        "tls-parser>=1.2.0,<1.3.0",
        "typing_extensions ; python_version<'3.8'",  # To remove when we drop support for Python 3.7
    ],
    # cx_freeze info for Windows builds with Python embedded
    options={"build_exe": {"packages": ["cffi", "cryptography", "idna"], "include_files": get_include_files()}},
    executables=[Executable(path.join("sslyze", "__main__.py"), targetName="sslyze.exe")],
)
