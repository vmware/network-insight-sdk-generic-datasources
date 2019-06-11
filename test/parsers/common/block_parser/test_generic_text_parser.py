import unittest
from network_insight_sdk_generic_datasources.parsers.common.text_parser import TextProcessor
from network_insight_sdk_generic_datasources.parsers.common.text_parser import Rule
from network_insight_sdk_generic_datasources.parsers.common.text_parser import GenericTextParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import SimpleBlockParser
from network_insight_sdk_generic_datasources.parsers.text.text_processor import rule_match_callback


class GenericTextParserTestCase(unittest.TestCase):
    def test_parser(self):
        text = """mtu is 1234 bytes
        ipaddress is 192.168.1.1"""
        mtu_regex = "mtu is (\\d+) bytes"
        ip_regex = "ipaddress is (.*)"
        rules = dict(mtu=mtu_regex, ip=ip_regex)
        parser = GenericTextParser()
        result = parser.parse(text, rules)
        self.assertEqual(result[0]['mtu'], '1234')
        self.assertEqual(result[0]['ip'], '192.168.1.1')

    def test_text_parser(self):
        text = """mtu is 1234 bytes
                ipaddress is 192.168.1.1
                
                mtu is 1234 bytes
                ipaddress is 192.168.1.1"""
        mtu_regex = "mtu is (\\d+) bytes"
        ip_regex = "ipaddress is (.*)"
        parser = TextProcessor(SimpleBlockParser())
        parser.add_rule(Rule('mtu', mtu_regex, rule_match_callback))
        parser.add_rule(Rule('ip', ip_regex, rule_match_callback))
        result = parser.process(text)
        self.assertEqual(len(result), 2)


if __name__ == '__main__':
    unittest.main()
