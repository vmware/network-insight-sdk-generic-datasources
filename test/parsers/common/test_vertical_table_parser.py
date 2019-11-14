import unittest
from parsers.common.vertical_table_parser import VerticalTableParser


class VerticalTableParserTestCase(unittest.TestCase):
    def test_parser(self):
        parser = VerticalTableParser()
        text = """
                junk
                divvy_num_nodes_required: 1
                divvy_enum_nodes_required: 2
                junk
                junk
                """
        result = parser.parse(text)
        self.assertEqual(len(result), 1)
        self.assertEqual(type(result), list)


if __name__ == '__main__':
    unittest.main()
