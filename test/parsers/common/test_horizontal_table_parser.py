import unittest
from network_insight_sdk_generic_datasources.parsers.common.horizontal_table_parser import HorizontalTableParser


class HorizontalTableParserTestCase(unittest.TestCase):
    def test_parser(self):
        text = """VNI      IP              MAC               Connection-ID 
        6796     192.168.139.11  00:50:56:b2:30:6e 1             
        6796     192.168.138.131 00:50:56:b2:40:33 2             
        6796     192.168.139.201 00:50:56:b2:75:d1 3 """
        parser = HorizontalTableParser()
        result = parser.parse(text)
        self.assertEqual(len(result), 3)
        self.assertEqual(len(result[0]), 4)
        self.assertEqual(len(result[1]), 4)
        self.assertEqual(len(result[2]), 4)


if __name__ == '__main__':
    unittest.main()
