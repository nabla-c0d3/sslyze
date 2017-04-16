#!/usr/bin/python
import sys
import unittest
import os


def main(test_path):
    # Add nassl to the path
    sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'lib'))
    # Increase SSLyze timeout to 10s
    from sslyze.utils.ssl_connection import SSLConnection
    SSLConnection.set_global_network_settings(network_max_retries=3, network_timeout=10)
    suite = unittest.loader.TestLoader().discover(test_path)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    exit_code = 0 if result.wasSuccessful() else 1
    sys.exit(exit_code)

if __name__ == '__main__':
    main('tests')

