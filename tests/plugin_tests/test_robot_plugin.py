# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from tls_parser.tls_version import TlsVersionEnum

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum, RobotPmsPaddingPayloadEnum, \
    RobotClientKeyExchangePayloads
from sslyze.server_connectivity import ServerConnectivityInfo


class RobotPluginPluginTestCase(unittest.TestCase):

    def test_robot_attack_good(self):
        server_info = ServerConnectivityInfo(hostname='www.facebook.com')
        server_info.test_connectivity_to_server()

        plugin = RobotPlugin()
        plugin_result = plugin.process_task(server_info, RobotScanCommand())

        self.assertEqual(plugin_result.robot_result_enum, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_robot_attack_bad(self):
        # TODO(AD): Find a vulnerable server?
        pass


class RobotClientKeyExchangePayloadsTestCase(unittest.TestCase):

    # RSA parameters from guide.duo.com on 01/2018
    _MODULUS = 21676321702992892544184210668533007938320008371099869414397347744230831476303641029718581379501139423025760050699248669009722622856375901598207737717965840143240998787525703816693218813971607619633906756107178755179895896841849419432167808470976931775353434578860350010062097449436748922107926597753594777265159321396127177933175457106276841953085647486726646355975033696522565552547629855710240681471056619766931976539898666308623498016952734309851047238444110091633182583357071556159295200575997822777900819329132169346643292942846820715401293858722526713520460407684626694058303256096130754649933055306227219197753
    _EXPONENT = 65537

    def test_get_client_key_exchange_record(self):
        # Validate the bug fix for https://github.com/nabla-c0d3/sslyze/issues/282
        for enum in RobotPmsPaddingPayloadEnum:
            cke_record = RobotClientKeyExchangePayloads.get_client_key_exchange_record(
                enum,
                TlsVersionEnum.TLSV1_2,
                self._MODULUS,
                self._EXPONENT
            )
            # The size of the record must always be the same for every ROBOT payload
            self.assertEqual(len(cke_record.to_bytes()), 267)
