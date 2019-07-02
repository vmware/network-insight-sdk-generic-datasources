import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperVRFTableProcessor
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperSwitchPortTableProcessor
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperRouterInterfaceTableProcessor
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperPortChannelTableProcessor
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperMACTableTableProcessor


class JuniperVRFTableProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        input_table = {'showVRFInterface': [{'interfaces': '', 'name': 'master'},
                                            {'interfaces': 'reth0.50,reth0.51,reth0.1564', 'name': 'dmz-vr'}]}
        expected_output = [{'name': 'master'}, {'name': 'dmz-vr'}]

        table_processor = JuniperVRFTableProcessor()
        table = table_processor.process_tables(input_table)
        self.assertEqual(len(table), 2)
        self.assertEqual(type(table), list)
        self.assertEqual(expected_output, table)


class JuniperSwitchPortTableProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        input_table = {'showInterface': [{'name': 'reth0  ', 'administrativeStatus': 'UP', 'mtu': '1518',
                                          'operationalStatus': 'UP', 'connected': 'TRUE', 'members': '',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': ''},
                                         {'name': 'reth0.26', 'administrativeStatus': 'UP', 'mtu': '1518',
                                          'operationalStatus': 'UP', 'connected': 'TRUE',
                                          'members': 'ge-0/0/4.26,ge-0/0/5.26,ge-9/0/4.26,ge-9/0/5.26',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': '213.207.10.56/26'}],
                       'showConfigInterface': [{'interface': 'reth0', 'vlan': '26', 'unit': '26'}]}
        expected_output = [{'name': 'reth0  ', 'administrativeStatus': 'UP', 'switchPortMode': 'ACCESS', 'mtu': '1518',
                            'operationalStatus': 'UP', 'connected': 'TRUE', 'hardwareAddress': '00:10:db:ff:8c:00',
                            'vlans': '0'}]
        table_processor = JuniperSwitchPortTableProcessor()
        table = table_processor.process_tables(input_table)
        self.assertEqual(len(table), 1)
        self.assertEqual(type(table), list)
        self.assertEqual(expected_output, table)


class JuniperRouterInterfaceTableProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        input_table = {'showInterface': [{'name': 'reth0  ', 'administrativeStatus': 'UP', 'mtu': '1518',
                                          'operationalStatus': 'UP', 'connected': 'TRUE', 'members': '',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': '', 'vlans': '0'},
                                         {'name': 'reth0.26', 'administrativeStatus': 'UP', 'mtu': '1518',
                                          'operationalStatus': 'UP', 'connected': 'TRUE', 'vlans': '26',
                                          'members': 'ge-0/0/4.26,ge-0/0/5.26,ge-9/0/4.26,ge-9/0/5.26',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': '213.207.10.56/26'}],
                       'showConfigInterface': [{'interface': 'reth0', 'vlan': '26', 'unit': '26'}],
                       'showVRFInterface': [{'interfaces': '', 'name': 'master'},
                                            {'interfaces': 'reth0.50,reth0.51,reth0.1564', 'name': 'dmz-vr'}]}

        expected_output = [{'name': 'reth0.26', 'vlan': '26', 'administrativeStatus': 'UP',
                            'mtu': '1518', 'operationalStatus': 'UP', 'connected': 'TRUE', 'vrf': 'master',
                            'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': '213.207.10.56/26'}]
        table_processor = JuniperRouterInterfaceTableProcessor()
        table = table_processor.process_tables(input_table)
        self.assertEqual(len(table), 1)
        self.assertEqual(type(table), list)
        self.assertEqual(expected_output, table)


class JuniperPortChannelTableProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        input_table = {'showInterface': [{'name': 'reth0  ', 'administrativeStatus': 'UP', 'switchPortMode': 'ACCESS',
                                          'mtu': '1518', 'operationalStatus': 'UP', 'connected': 'TRUE',
                                          'vrf': 'master', 'members': '', 'hardwareAddress': '00:10:db:ff:8c:00',
                                          'vlans': '0', 'ipAddress': ''},
                                         {'name': 'reth0.26', 'administrativeStatus': 'UP', 'switchPortMode': 'TRUNK',
                                          'mtu': '1518', 'operationalStatus': 'UP', 'connected': 'TRUE',
                                          'vrf': 'master', 'members': 'ge-0/0/4.26,ge-0/0/5.26,ge-9/0/4.26,ge-9/0/5.26',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'vlans': '26',
                                          'ipAddress': '213.207.10.56/26'}]}

        expected_output = [{'name': 'reth0.26', 'administrativeStatus': 'UP', 'switchPortMode': 'TRUNK', 'mtu': '1518',
                            'operationalStatus': 'UP', 'connected': 'TRUE', 'vrf': 'master',
                            'hardwareAddress': '00:10:db:ff:8c:00', 'vlans': '26'}]
        table_processor = JuniperPortChannelTableProcessor()
        table = table_processor.process_tables(input_table)
        self.assertEqual(len(table), 1)
        self.assertEqual(type(table), list)
        self.assertEqual(expected_output, table)


class JuniperMACTableTableProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        input_table = {'showInterface': [{'name': 'reth0.40', 'administrativeStatus': 'UP', 'switchPortMode': 'ACCESS',
                                          'mtu': '1518', 'operationalStatus': 'UP', 'connected': 'TRUE',
                                          'vrf': 'master', 'members': 'ge-0/0/4.26,ge-0/0/5.26,ge-9/0/4.26,ge-9/0/5.26',
                                          'hardwareAddress': '00:10:db:ff:8c:00', 'vlans': '0',
                                          'ipAddress': '213.207.10.56/26'}],
                       'showMacTable': [{'macAddress': '78:fe:3d:37:6e:c1', 'switchPort': 'reth0.40', 'vlan': '0',
                                         'address': '172.25.97.254', 'Flags': 'none'}]}
        expected_output = [{'macAddress': '78:fe:3d:37:6e:c1', 'switchPort': 'reth0.40', 'vlan': '0'}]
        table_processor = JuniperMACTableTableProcessor()
        table = table_processor.process_tables(input_table)
        self.assertEqual(len(table), 1)
        self.assertEqual(type(table), list)
        self.assertEqual(expected_output, table)

if __name__ == '__main__':
    unittest.main()
