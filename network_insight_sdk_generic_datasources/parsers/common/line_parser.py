import re


class LineTokenizer(object):
    """
    Tokenizes the line to individual words which are separated by space(s) by default.
    """
    REGEX_TOKENIZER = '\\s+'

    def __init__(self, regex=REGEX_TOKENIZER):
        self.regex = regex

    def tokenize(self, line=None):
        """
        Tokenizes based on regex
        @param line:
        @return:
        """
        if line is None or line.strip() == '':
            raise ValueError('Line not provided')
        line = line.strip()
        array = re.split(self.regex, str(line))
        return array
