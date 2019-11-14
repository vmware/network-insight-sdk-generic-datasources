import unittest
from parsers.common.line_parser import LineTokenizer


class LineTokenizerTestCase(unittest.TestCase):
    def test_tokenize(self):
        lt = LineTokenizer()
        fields = lt.tokenize("Hello                      World                 Tokenize")
        print (fields)
        self.assertEqual(len(fields), 3)


if __name__ == '__main__':
    unittest.main()
