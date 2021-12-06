# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from network_insight_sdk_generic_datasources.common.log import py_logger


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
        @return: array after splitting with regex
        """
        if line is None or line.strip() == '':
            py_logger.info("Line is null or empty")
            return None
        line = line.strip()
        array = re.split(self.regex, str(line))
        return array
