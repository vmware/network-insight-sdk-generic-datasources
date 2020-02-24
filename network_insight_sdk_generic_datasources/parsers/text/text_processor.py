# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from functools import partial

from network_insight_sdk_generic_datasources.parsers.common.line_parser import LineTokenizer
from network_insight_sdk_generic_datasources.parsers.common.block_parser import BlockParser


class TextProcessor(object):

    def __init__(self, block_parser=None, line_tokenizer=LineTokenizer()):
        """
        Text Processor parses block of text line by line based on Rules
        Each rule contain key and regex pattern for key. Once Rule is applied successfully.
        Key of Rule is assigned with value matches with pattern.
        Regex pattern must have one group (regex groups) for Key of Rule to be assigned with value.
        @param block_parser:
        @param line_tokenizer:
        """
        if block_parser is not None:
            if not isinstance(block_parser, BlockParser):
                raise ValueError("block parser not provided")

        if not isinstance(line_tokenizer, LineTokenizer):
            raise ValueError("line parser not provided")
        self.block_parser = block_parser
        self.line_tokenizer = line_tokenizer
        self.rules = list()

    def process(self, text):
        """
        @param text:
        @return: List of Key Value Pairs
        """
        if self.block_parser is not None:
            blocks = self.block_parser.parse(text)
        else:
            blocks = list()
            blocks.append(text)
        result = []
        for block in blocks:
            lines = block.splitlines()
            total_lines = len(lines)
            current_line_number = 0
            row = {}
            while current_line_number < total_lines:
                current_line = lines[current_line_number]
                for rule in self.rules:
                    match = rule.get_pattern_match(current_line)
                    if match is not None:
                        parsed_key_values = {}
                        fields = self.line_tokenizer.tokenize(current_line)
                        input_lines = lines if type(rule) == BlockRule else current_line
                        rule.apply(current_line_number, input_lines, fields, match.groups(), parsed_key_values)
                        row.update(parsed_key_values)
                # End of for loop
                current_line_number += 1
            # Adding field_name with empty string if value not found
            row.update({i.field_name: "" for i in self.rules if i.field_name not in row.keys()})
            result = result + [row]
        return result

    def add_rule(self, rule):
        self.rules.append(rule)
        return self


class Rule(object):
    def __init__(self, field_name, pattern, callback):
        self.pattern = pattern
        self.field_name = field_name
        self.callback = callback

    def get_pattern_match(self, line):
        pattern = re.compile(self.pattern)
        return pattern.match(line.strip())

    def apply(self, line_number, line, fields, groups, keyval):
        params = dict({'line_number': line_number,
                       'fields': fields,
                       'groups': groups,
                       'line': line,
                       'keyval': keyval,
                       'field_name': self.field_name})
        partial(self.callback, **params)()


def rule_match_callback(**kwargs):
    keyval = kwargs['keyval']
    groups = kwargs['groups']
    field_name = kwargs['field_name']
    if groups is not None and len(groups) > 0:
        keyval[field_name] = groups[0]


class BlockRule(Rule):
    """
    Find N from regular expression for current line, and then return next N lines
    line_number: Current line number
    lines: All set of lines for extracting the next N lines based on match
    fields: Fields tokenized from current line
    groups: Pattern match for current line based on regular expression
    keyval: Key value pair which is ultimately returned
    """
    def apply(self, line_number, lines, fields, groups, keyval):
        super().apply(line_number, lines[line_number], fields, groups, keyval)
        retrieve_line_count = int(list(keyval.values())[0])
        count = 1
        retrieve_val = ''
        while line_number + count < len(lines) and count <= retrieve_line_count:
            retrieve_val += lines[line_number + count]
            if count != retrieve_line_count:
                retrieve_val += '\n'
            count += 1
        keyval.update({list(keyval.keys())[0]: retrieve_val})
