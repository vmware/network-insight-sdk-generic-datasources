import unittest
from network_insight_sdk_generic_datasources.parsers.common.horizontal_table_parser import HorizontalTableParser


class JuniperHorizontalTableParserTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """\nMAC Address       Address         Interface         Flags
                    58:00:bb:5b:29:30 30.65.0.2       fab0.0                   permanent
                    d0:07:ca:76:99:30 30.66.0.1       fab1.0                   permanent"""

        expected_output = [{'macAddress': u'58:00:bb:5b:29:30', 'switchPort': u'fab0.0', 'Flags': u'permanent',
                            'address': u'30.65.0.2'},
                           {'macAddress': u'd0:07:ca:76:99:30', 'switchPort': u'fab1.0', 'Flags': u'permanent',
                            'address': u'30.66.0.1'}]

        header_keys = ['macAddress', 'address', 'switchPort', 'Flags']
        parser = HorizontalTableParser()
        result = parser.parse(text, skip_head=1, skip_tail=None, header_keys=header_keys)
        self.assertEqual(len(result), 2)
        self.assertEqual(type(result), list)
        self.assertEqual(expected_output[0], result[0])
        self.assertEqual(expected_output[1], result[1])


if __name__ == '__main__':
    unittest.main()
