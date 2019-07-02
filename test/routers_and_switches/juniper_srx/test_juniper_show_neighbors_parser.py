import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import JuniperNeighborsTableParser
from network_insight_sdk_generic_datasources.parsers.common.horizontal_table_parser import HorizontalTableParser


class JuniperDevicePrePostProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """\nLocal Interface    Parent Interface    Chassis Id          Port info          System Name
            ge-9/0/5           reth0               78:fe:3d:37:6e:c0   fw2.dp - ge-0/0/5 (ae3) sw1.rdm.nl.rgtn.com
            ge-0/0/5           reth0               78:fe:3d:37:6e:c0   fw1.dp - ge-0/0/5 (ae2) sw1.rdm.nl.rgtn.com"""

        expected_output = [{'localInterface': 'ge-9/0/5', 'remoteInterface': 'ge-0/0/5', 'remoteDevice': 'sw1.rdm.nl.rgtn.com'},
                           {'localInterface': 'ge-0/0/5', 'remoteInterface': 'ge-0/0/5', 'remoteDevice': 'sw1.rdm.nl.rgtn.com'}]

        parser = JuniperNeighborsTableParser()
        result = parser.parse(text)
        self.assertEqual(len(result), 2)
        self.assertEqual(type(result), list)
        self.assertEqual(expected_output[0], result[0])
        self.assertEqual(expected_output[1], result[1])


if __name__ == '__main__':
    unittest.main()
