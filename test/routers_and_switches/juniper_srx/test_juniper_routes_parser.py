import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import JuniperRoutesParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser


class JuniperDevicePrePostProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """inet.0: 86 destinations, 129 routes (63 active, 0 holddown, 43 hidden)
0.0.0.0/0 (3 entries, 1 announced)
        *BGP    Preference: 170/-101
                Next hop type: Router, Next hop index: 1401
                Address: 0x19a1150
                Next-hop reference count: 33
                Source: 77.73.224.160
                Next hop: 77.73.224.160 via reth0.470, selected
                Session Id: 0x0
                State: <Active Ext>
                Peer AS: 41960
                Age: 4w5d 12:13:18 	Metric: 10
                Validation State: unverified
                Task: BGP_41960_51299.77.73.224.160
                Announcement bits (2): 0-KRT 2-OSPF
                AS path: 41960 I
                Accepted
                Localpref: 100
                Router ID: 195.238.86.36
dmz-vr.inet.0: 11 destinations, 11 routes (11 active, 0 holddown, 0 hidden)

0.0.0.0/0 (1 entry, 1 announced)
        *Static Preference: 5
                Next hop type: Router, Next hop index: 1402
                Address: 0x19a11ac
                Next-hop reference count: 3
                Next hop: 185.158.146.1 via reth0.1564, selected
                Session Id: 0x0
                State: <Active Int Ext>
                Age: 16w0d 17:18:09
                Validation State: unverified
                Task: RT
                Announcement bits (2): 1-KRT 2-Resolve tree 2
                AS path: I"""

        expected_output = [[{'interfaceName': 'reth0.470', 'network': '0.0.0.0/0', 'name': '0.0.0.0/0_0',
                            'nextHop': '77.73.224.160', 'routeType': 'BGP', 'vrf': 'master'}],
                           [{'interfaceName': 'reth0.1564', 'network': '0.0.0.0/0', 'name': '0.0.0.0/0_0',
                             'nextHop': '185.158.146.1', 'routeType': 'Static', 'vrf': 'dmz-vr'}]]


        parser = LineBasedBlockParser('(.*): \d* destinations')
        data = parser.parse(text)

        parser = JuniperRoutesParser()
        for i, block in enumerate(data):
            result = parser.parse(block)
            self.assertEqual(len(result), 1)
            self.assertEqual(type(result), list)
            self.assertEqual(expected_output[i][0], result[0])


if __name__ == '__main__':
    unittest.main()
