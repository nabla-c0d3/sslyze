from os import path, listdir

from setuptools import setup, find_packages
from sslyze import __author__, __email__, __version__
from cx_Freeze import setup, Executable

# Setup file based on https://github.com/pypa/sampleproject/blob/master/setup.py
root_path = path.abspath(path.dirname(__file__))


def get_long_description():
    """Convert the README file into the long description.
    """
    with open(path.join(root_path, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
    return long_description


def get_include_files():
    """"Get the list of trust stores so they properly packaged when doing a cx_freeze build.
    """
    plugin_data_files = []
    trust_stores_pem_path = path.join(root_path, 'sslyze', 'plugins', 'utils', 'trust_store', 'pem_files')
    for file in listdir(trust_stores_pem_path):
        file = path.join(trust_stores_pem_path, file)
        if path.isfile(file):  # skip directories
            filename = path.basename(file)
            plugin_data_files.append((file, path.join('pem_files', filename)))
    return plugin_data_files


setup(
    name='sslyze',
    version=__version__,
    description='Fast and powerful SSL/TLS server scanning library',
    python_requires='>=3.6',

    # Pypi metadata
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/nabla-c0d3/sslyze',
    author=__author__,
    author_email=__email__,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: French',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3.6',
        'Topic :: System :: Networking',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
    ],
    keywords='ssl tls scan security library',
    project_urls={
        'Source': 'https://github.com/nabla-c0d3/sslyze',
        'Changelog': 'https://github.com/nabla-c0d3/sslyze/releases',
        'Documentation': 'https://nabla-c0d3.github.io/sslyze/documentation',
    },

    # Package info
    packages=find_packages(exclude=['docs', 'tests']),
    package_data={'sslyze.plugins.utils.trust_store': ['pem_files/*.pem', 'pem_files/*.yaml']},
    entry_points={'console_scripts': ['sslyze = sslyze.__main__:main']},

    # Dependencies
    install_requires=[
        'nassl>=1.1.0,<1.2.0',
        'cryptography==2.2.2',
        'tls-parser>=1.2.0,<1.3.0'
    ],

    # cx_freeze info for Windows builds with Python embedded
    options={"build_exe": {
        "packages": ['cffi', 'cryptography', 'idna'],
        'include_files': get_include_files(),}
    },
    executables=[Executable(path.join('sslyze', '__main__.py'), targetName='sslyze.exe')],
)
