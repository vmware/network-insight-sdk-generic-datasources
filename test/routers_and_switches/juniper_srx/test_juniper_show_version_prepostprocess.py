import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperDevicePrePostProcessor
from network_insight_sdk_generic_datasources.parsers.common.vertical_table_parser import VerticalTableParser


class JuniperDevicePrePostProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """\nnode0:\n--------------------------------------------------------------------------
        \nHostname: fw1.rdm.nl.rgtn.com
        \nModel: srx550m
        \nJunos: 15.1X49-D150.2
        \nJUNOS Software Release [15.1X49-D150.2]
        \n\nnode1:
        \n--------------------------------------------------------------------------
        \nHostname: fw2.rdm.nl.rgtn.com
        \nModel: srx550m
        \nJunos: 15.1X49-D150.2
        \nJUNOS Software Release [15.1X49-D150.2]\n'"""

        expected_output = {'vendor': 'Juniper', 'name': 'Juniper-srx550m',
                           'hostname': 'fw1.rdm.nl.rgtn.com',
                           'ipAddress/fqdn': '10.40.13.37', 'model': 'srx550m', 'os': 'JUNOS 15.1X49-D150.2'}
        parser = VerticalTableParser()
        data = parser.parse(text)
        device = JuniperDevicePrePostProcessor()
        result = device.post_process(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(type(result), list)
        self.assertEqual(expected_output, result[0])


if __name__ == '__main__':
    unittest.main()
