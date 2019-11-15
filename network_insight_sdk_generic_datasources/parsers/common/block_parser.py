# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from network_insight_sdk_generic_datasources.common.log import py_logger


class BlockParser(object):
    """
    Abstract class for writing new block parser if none of supported block parser is able to parse text.
    Defines contract for writing new block parsers.
    Iterates through paragraph line by line and Parses based on 'start of line' and 'end of line'
    """

    def __init__(self):
        self.has_block_started = False
        self.has_block_ended = True
        self.prev_line = None
        self.current_line_number = -1
        self.next_line = None

    def _set_previous_line(self, total_lines, lines, i):
        if total_lines == 0:
            return
        if i == 0:
            self.prev_line = None
        else:
            self.prev_line = str(lines[i - 1])

    def _set_next_line(self, total_lines, lines, i):
        if i + 1 >= total_lines:
            self.next_line = None
        else:
            self.next_line = str(lines[i + 1])

    def newline_if_required(self):
        if self.has_block_started and not self.has_block_ended:
            return '\n'
        else:
            return ''

    def parse(self, text):
        """
        Parser output and tokenizes block
        :param text: 
        :return: line_number and block  
        """
        lines = text.splitlines()
        i = 0
        total_lines = len(lines)
        blocks = list()
        block = None
        while i < total_lines:
            self.current_line_number = i
            self._set_previous_line(total_lines, lines, i)
            self._set_next_line(total_lines, lines, i)
            current_line = str(lines[i]).strip()

            if self.is_start_of_block(current_line, i) and self.has_block_ended:
                self.has_block_started = True
                self.has_block_ended = False

            if self.has_block_started and not self.has_block_ended:
                # Block has been initialize now we can add lines to block
                block = ('' if block is None else block) + current_line
            else:
                py_logger.info("Ignoring line {}".format(current_line))

            if self.is_end_of_block(current_line, i):
                blocks.append(block.strip())
                self.has_block_started = False
                self.has_block_ended = True
                block = None
            if block is not None:
                block = block + self.newline_if_required()
            i += 1
        return blocks

    def is_start_of_block(self, line, line_number):
        if self.has_block_ended and (self.prev_line is None or self.block_start_function(line, line_number)):
            return True
        return False

    def is_end_of_block(self, line, line_number):
        if self.next_line is None:
            return True
        if self.has_block_started and self.block_end_function(line, line_number):
            return True
        return False

    def block_start_function(self, line, line_number):
        """
        @return: true if start of block
        """
        raise NotImplemented('Should be implemented in child class')

    def block_end_function(self, line, line_number):
        """
        @return: true if end of block
        """
        raise NotImplemented('Should be implemented in child class')


class SimpleBlockParser(BlockParser):
    """
    Simple Block parser extracts blocks if blank line detected
    """

    def __init__(self):
        super(SimpleBlockParser, self).__init__()

    def block_start_function(self, line, line_number):
        if self.prev_line is None:
            return True
        return self.prev_line.strip() == ''

    def block_end_function(self, line, line_number):
        return len(line) == 0


class PatternBasedBlockParser(BlockParser):
    """
    Creates block from text based on start pattern and end pattern.
    """
    def __init__(self, start_pattern, end_pattern):
        super(PatternBasedBlockParser, self).__init__()
        self.start_pattern = start_pattern
        self.end_pattern = end_pattern

    def is_start_of_block(self, line, line_number):
        return self.is_pattern_match(self.start_pattern, line)

    def is_end_of_block(self, line, line_number):
        return self.is_pattern_match(self.end_pattern, line)

    @staticmethod
    def is_pattern_match(pattern, line):
        pattern = re.compile(pattern)
        match = re.search(pattern, line)
        if match:
            return True
        else:
            return False


class LineBasedBlockParser(BlockParser):
    """
    Creates blocks from text based on pattern which reappears after certain lines.
    """
    def __init__(self, line_pattern):
        super(LineBasedBlockParser, self).__init__()
        self.line_pattern = line_pattern

    def block_start_function(self, line, line_number):
        return re.search(self.line_pattern, line) is not None

    def block_end_function(self, line, line_number):
        return re.search(self.line_pattern, self.next_line) is not None


class GenericBlockParser(BlockParser):
    """
    Generic Block parser is common handler for parsing blocks. GenericBlockParser uses specific block parser internally.
    There is no generic logic for GenericBlockParser.
    """
    def __init__(self, **kwargs):
        if 'start_pattern' in kwargs and 'end_pattern' in kwargs:
            self.parser = PatternBasedBlockParser(**kwargs)

        if 'line_pattern' in kwargs:
            self.parser = LineBasedBlockParser(**kwargs)

    def parse(self, text):
        return self.parser.parse(text)
