import unittest
from parsers.common.block_parser import SimpleBlockParser
from parsers.common.block_parser import LineBasedBlockParser


class BlockParserTestCase(unittest.TestCase):
    def test_generic_block_parser(self):
        para = """Hello world b1 1
                Hello world b1 2
                Hello world b1 3

                Hello world b2 1
                Hello world b2 2
                Hello world b2 3
                """
        bt = SimpleBlockParser()
        blocks = bt.parse(para)
        self.assertEqual(len(blocks), 2)

    def test_line_based_block_parser(self):
        para = """Hello world b1 1
                        Hello world b1 2
                        Hello world b1 3

                        Hello world b2 1
                        Hello world b2 2
                        Hello world b2 3
                        """
        regex_pattern = 'Hello world b\\d 1'
        parser = LineBasedBlockParser(regex_pattern)
        blocks = parser.parse(para)
        self.assertEqual(len(blocks), 2)


if __name__ == '__main__':
    unittest.main()
