# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

# All Vertical data parsing classes go in this file
import copy


class VerticalTableParser(object):
    """
    Output like below can be parsed with vertical table parser
    Eth1:
        MTU: 1500
        DUPLEX: HALF

    >>> from network_insight_sdk_generic_datasources.parsers.common.vertical_table_parser import VerticalTableParser
    >>> import pprint
    >>> text = '''Eth1:
    ...    MTU: 1500
    ...    DUPLEX: HALF'''
    >>> parser = VerticalTableParser()
    >>> pprint.pprint(parser.parse(text))
    """

    def parse(self, text, delimiter=':', skip_head=0, skip_tail=0):
        """
        Calling the parse function will return array
        @param text: 
        @param delimiter:
        @param skip_head: no. of lines to skip from top or head
        @param skip_tail: no. of lines to skip from bottom or tail
        @return:
        """
        data = []
        lines = text.strip().split("\n")
        if ((len(lines) > 0) and ((lines[0].upper().find("ERROR") > 0) or
                                  (lines[0].upper().find("NOT FOUND") > 0) or
                                  (len(lines) == 1 and lines[0].strip() == ""))):
            return data

        start_line = skip_head
        end_line = len(lines) - skip_tail
        i = start_line
        while i < end_line:
            if lines[i].strip() != "":
                data.append(lines[i].rstrip())
            i += 1

        pydicts = self.recurse_vertical_data_parser(data, delimiter)
        return pydicts

    def recurse_vertical_data_parser(self, text, delimiter=':'):
        data = []
        if len(text) == 0:
            return data
        current_block_indent = self.get_indent(text[0])
        index = 0
        while index < len(text):
            # Ignore lines which does not contain delimiter
            if delimiter not in text[index]:
                index += 1
                continue
            ########################
            if index + 1 != len(text) and (self.get_indent(text[index + 1]) > current_block_indent):
                pydict = {}
                (key, value) = text[index].split(delimiter, 1)
                new_input = []
                index = index + 1
                while index != len(text) and self.get_indent(text[index]) > current_block_indent:
                    new_input.append(text[index])
                    index = index + 1
                new_block_hash = self.recurse_vertical_data_parser(new_input, delimiter)
                if value.strip() != '':
                    new_block_hash.insert(0, {key.strip(): value.strip()})
                pydict.update({key.strip(): copy.deepcopy(new_block_hash)})
                data.append({key.strip(): new_block_hash})
            else:
                pydict = {}
                (key, value) = text[index].split(delimiter, 1)
                pydict.update({key.strip(): value.strip()})
                data.append(pydict)
                index = index + 1
        return data

    @staticmethod
    def get_indent(string):
        sub_str = string.lstrip()
        return string.find(sub_str)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
