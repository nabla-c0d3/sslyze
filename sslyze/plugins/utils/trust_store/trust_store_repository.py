import tarfile
import io
import os
import shutil
from tempfile import mkdtemp

from urllib.request import urlretrieve


from os.path import join
import inspect
import sys
from os.path import abspath, realpath, dirname
from sslyze.plugins.utils.trust_store.trust_store import TrustStore
from typing import List, Tuple


def _get_script_dir(follow_symlinks: bool = True) -> str:
    # Getting the path to the trust stores is tricky due to subtle differences on OS X, Linux and Windows
    if getattr(sys, 'frozen', False):
        # py2exe, PyInstaller, cx_Freeze
        path = abspath(sys.executable)
    else:
        path = inspect.getabsfile(_get_script_dir)
    if follow_symlinks:
        path = realpath(path)
    return dirname(path)


_MOZILLA_EV_OIDS = ['1.2.276.0.44.1.1.1.4', '1.2.392.200091.100.721.1', '1.2.40.0.17.1.22',
                    '1.2.616.1.113527.2.5.1.1', '1.3.159.1.17.1', '1.3.6.1.4.1.13177.10.1.3.10',
                    '1.3.6.1.4.1.14370.1.6', '1.3.6.1.4.1.14777.6.1.1', '1.3.6.1.4.1.14777.6.1.2',
                    '1.3.6.1.4.1.17326.10.14.2.1.2', '1.3.6.1.4.1.17326.10.14.2.2.2',
                    '1.3.6.1.4.1.17326.10.8.12.1.2', '1.3.6.1.4.1.17326.10.8.12.2.2', '1.3.6.1.4.1.22234.2.5.2.3.1',
                    '1.3.6.1.4.1.23223.1.1.1', '1.3.6.1.4.1.29836.1.10', '1.3.6.1.4.1.34697.2.1',
                    '1.3.6.1.4.1.34697.2.2', '1.3.6.1.4.1.34697.2.3', '1.3.6.1.4.1.34697.2.4',
                    '1.3.6.1.4.1.36305.2', '1.3.6.1.4.1.40869.1.1.22.3', '1.3.6.1.4.1.4146.1.1',
                    '1.3.6.1.4.1.4788.2.202.1', '1.3.6.1.4.1.6334.1.100.1', '1.3.6.1.4.1.6449.1.2.1.5.1',
                    '1.3.6.1.4.1.782.1.2.1.8.1', '1.3.6.1.4.1.7879.13.24.1', '1.3.6.1.4.1.8024.0.2.100.1.2',
                    '2.16.156.112554.3', '2.16.528.1.1003.1.2.7', '2.16.578.1.26.1.3.3', '2.16.756.1.83.21.0',
                    '2.16.756.1.89.1.2.1.1', '2.16.792.3.0.3.1.1.5', '2.16.792.3.0.4.1.1.4',
                    '2.16.840.1.113733.1.7.23.6', '2.16.840.1.113733.1.7.48.1', '2.16.840.1.114028.10.1.2',
                    '2.16.840.1.114171.500.9', '2.16.840.1.114404.1.1.2.4.1', '2.16.840.1.114412.2.1',
                    '2.16.840.1.114413.1.7.23.3', '2.16.840.1.114414.1.7.23.3', '2.16.840.1.114414.1.7.24.3']


class TrustStoresRepository:
    """The list of default trust stores used by SSLyze for certificate validation.
    """

    _DEFAULT_TRUST_STORES_PATH = join(_get_script_dir(), 'pem_files')

    _DEFAULT_REPOSITORY = None  # Singleton we use to avoid parsing the trust stores over and over

    _STORE_PRETTY_NAMES = {
        'APPLE_IOS': 'iOS',
        'APPLE_MACOS': 'macOS',
        'GOOGLE_AOSP': 'Android',
        'MICROSOFT_WINDOWS': 'Windows',
        'MOZILLA_NSS': 'Mozilla',
        'ORACLE_JAVA': 'Java',
    }

    _MOZILLA_STORE_NAME = 'MOZILLA_NSS'

    def __init__(self, repository_path: str) -> None:
        available_stores = {}
        for store_name, store_version, store_pem_path in self._parse_trust_stores_in_folder(repository_path):
            store_pretty_name = self._STORE_PRETTY_NAMES.get(store_name, store_name)

            ev_oids = None
            if store_name == self._MOZILLA_STORE_NAME:
                ev_oids = _MOZILLA_EV_OIDS

            store = TrustStore(store_pem_path, store_pretty_name, store_version, ev_oids)
            available_stores[store_name] = store

        self._available_stores = available_stores

    @staticmethod
    def _parse_trust_stores_in_folder(path: str) -> List[Tuple[str, str, str]]:
        available_store_names = set()
        for filename in os.listdir(path):
            # Only keep the name without the file extension
            available_store_names.add(filename.split('.')[0])

        available_stores = []
        for store_name in available_store_names:
            # The should be a .yaml and a .pem file
            store_pem_path = join(path, '{}.pem'.format(store_name))

            # Parse the YAML file
            store_yaml_path = join(path, '{}.yaml'.format(store_name))
            with io.open(store_yaml_path, encoding='utf-8') as store_yaml_file:
                # Manually parse so we don't add pyaml as a dependency
                store_info = store_yaml_file.read()
            store_name = store_info.split('platform: ', 1)[1].split('\n', 1)[0].strip()
            store_version = store_info.split('version: ', 1)[1].split('\n', 1)[0].strip(' \'')
            if store_name in ['MICROSOFT_WINDOWS', 'MOZILLA_NSS']:
                # Use the date_fetched instead
                store_version = store_info.split('date_fetched: ', 1)[1].split('\n', 1)[0].strip()

            available_stores.append((store_name, store_version, store_pem_path))

        return available_stores

    def get_all_stores(self) -> List[TrustStore]:
        return list(self._available_stores.values())

    def get_main_store(self) -> TrustStore:
        return self._available_stores[self._MOZILLA_STORE_NAME]

    @classmethod
    def get_default(cls) -> 'TrustStoresRepository':
        # Not thread-safe
        if cls._DEFAULT_REPOSITORY is None:
            cls._DEFAULT_REPOSITORY = cls(cls._DEFAULT_TRUST_STORES_PATH)
        return cls._DEFAULT_REPOSITORY

    _UPDATE_URL = 'https://nabla-c0d3.github.io/trust_stores_observatory/trust_stores_as_pem.tar.gz'

    @classmethod
    def update_default(cls) -> 'TrustStoresRepository':
        """Update the default trust stores used by SSLyze.

        The latest stores will be downloaded from https://github.com/nabla-c0d3/trust_stores_observatory.
        """
        temp_path = mkdtemp()
        try:
            # Download the latest trust stores
            archive_path = join(temp_path, 'trust_stores_as_pem.tar.gz')
            urlretrieve(cls._UPDATE_URL, archive_path)

            # Extract the archive
            extract_path = join(temp_path, 'extracted')
            tarfile.open(archive_path).extractall(extract_path)

            # Copy the files to SSLyze and overwrite the existing stores
            shutil.rmtree(cls._DEFAULT_TRUST_STORES_PATH)
            shutil.copytree(extract_path, cls._DEFAULT_TRUST_STORES_PATH)
        finally:
            shutil.rmtree(temp_path)

        # Re-generate the default repo - not thread-safe
        cls._DEFAULT_REPOSITORY = cls(cls._DEFAULT_TRUST_STORES_PATH)
        return cls._DEFAULT_REPOSITORY
