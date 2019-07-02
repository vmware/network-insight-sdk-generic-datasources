import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperConfigInterfacesPrePostProcessor
from network_insight_sdk_generic_datasources.parsers.common.block_parser import GenericBlockParser
from network_insight_sdk_generic_datasources.parsers.common.text_parser import GenericTextParser


class JuniperConfigInterfacesPrePostProcessorTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """set interfaces reth0 vlan-tagging
                set interfaces reth0 redundant-ether-options redundancy-group 1
                set interfaces reth0 redundant-ether-options lacp passive
                set interfaces reth0 unit 26 description "NL-IX NAWAS"
                set interfaces reth0 unit 26 vlan-id 26
                """

        expected_output = [{'interface': 'reth0', 'vlan': '26', 'unit': '26'}]


        rules = dict(unit=".*unit (.*) vlan-id .*", vlan=".*unit .* vlan-id (.*)",
                           interface="set interfaces (.*) unit .*")

        parser = GenericBlockParser(line_pattern="set interfaces")
        data = parser.parse(text)
        result = []
        for block in data:
            generic_text_parser = GenericTextParser()
            text_data = generic_text_parser.parse(block, rules=rules)

            device = JuniperConfigInterfacesPrePostProcessor()
            result = device.post_process(text_data)
        self.assertEqual(len(result), 1)
        self.assertEqual(type(result), list)
        self.assertEqual(expected_output, result)


if __name__ == '__main__':
    unittest.main()
