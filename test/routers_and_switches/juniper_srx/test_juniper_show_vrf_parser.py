import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import JuniperVRFParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import SimpleBlockParser


class JuniperShowVRFTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """master:
                  Router ID: 10.30.98.73
                  Type: forwarding        State: Active
                  Tables:
                    inet.0                 : 129 routes (63 active, 0 holddown, 43 hidden)
                    inet6.0                : 14 routes (13 active, 0 holddown, 1 hidden)

                dmz-vr:
                  Router ID: 10.10.253.1
                  Type: vrf               State: Active
                  Interfaces:
                    reth0.50
                    reth0.51
                    reth0.1564
                  Route-distinguisher: 185.158.146.251:10
                  Vrf-import: [ reject-all ]
                  Vrf-export: [ reject-all ]
                  Fast-reroute-priority: low
                  Tables:
                    dmz-vr.inet.0          : 11 routes (11 active, 0 holddown, 0 hidden)
                """

        expected_output = [[{'interfaces': '', 'name': 'master'}],
                           [{'interfaces': 'reth0.50,reth0.51,reth0.1564', 'name': 'dmz-vr'}]]
        parser = SimpleBlockParser()
        data = parser.parse(text)

        parser = JuniperVRFParser()
        for i, block in enumerate(data):
            result = parser.parse(block)
            if result:
                self.assertEqual(len(result), 1)
                self.assertEqual(type(result), list)
                self.assertEqual(expected_output[i][0], result[0])


if __name__ == '__main__':
    unittest.main()
