# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from os.path import join
import inspect
import sys
from os.path import abspath, realpath, dirname
from sslyze.plugins.utils.trust_store.trust_store import TrustStore
from typing import List


def _get_script_dir(follow_symlinks=True):
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


class TrustStoresRepository(object):
    """Retrieve the trust stores available for certificate validation.
    """

    _TRUST_STORES_PATH = join(_get_script_dir(), 'pem_files')

    _MAIN_STORE = TrustStore(join(_TRUST_STORES_PATH, 'mozilla.pem'), 'Mozilla', '09/2016', _MOZILLA_EV_OIDS)

    _ALL_STORES = [
        _MAIN_STORE,
        TrustStore(join(_TRUST_STORES_PATH, 'microsoft.pem'), 'Microsoft', '09/2016'),
        TrustStore(join(_TRUST_STORES_PATH, 'apple.pem'), 'Apple', 'OS X 10.11.6'),
        TrustStore(join(_TRUST_STORES_PATH, 'java.pem'), 'Java 7', 'Update 79'),
        TrustStore(join(_TRUST_STORES_PATH, 'aosp.pem'), 'AOSP', '7.0.0 r1'),
    ]

    @classmethod
    def get_all(cls):
        # type: () -> List[TrustStore]
        """Return all available trust stores.
        """
        return cls._ALL_STORES

    @classmethod
    def get_main(cls):
        # type: () -> TrustStore
        """Return the main trust store we use for certificate validation - for now we use Mozilla's.

        It is used for additional things including OCSP and EV validation.
        """
        return cls._MAIN_STORE
