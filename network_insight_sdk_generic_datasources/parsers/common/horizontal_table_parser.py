# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from common.log import py_logger


class HorizontalTableParser(object):

    """
    >>> horizontal_parser = HorizontalTableParser()
    >>> import pprint
    >>> header_keys = ['Mac Address', 'VTEP Label']
    >>> raw_data = '''
    ...     Mac Address             VTEP Label
    ...     -----------------       ----------
    ... '''
    >>> pprint.pprint(horizontal_parser.parse(
    ...     raw_data, header_keys=header_keys, skip_head=1,
    ...     skip_tail=1))
    []
    >>> raw_data = '''
    ... VNI      IP              MAC               Connection-ID
    ... 6796     192.168.139.11  00:50:56:b2:30:6e 1
    ... 6796     192.168.138.131 00:50:56:b2:40:33 2
    ... 6796     192.168.139.201 00:50:56:b2:75:d1 3
    ... '''
    >>> horizontal_parser = HorizontalTableParser()
    >>> pprint.pprint(horizontal_parser.parse(raw_data))
    [{'Connection-ID': '1',
      'IP': '192.168.139.11',
      'MAC': '00:50:56:b2:30:6e',
      'VNI': '6796'},
     {'Connection-ID': '2',
      'IP': '192.168.138.131',
      'MAC': '00:50:56:b2:40:33',
      'VNI': '6796'},
     {'Connection-ID': '3',
      'IP': '192.168.139.201',
      'MAC': '00:50:56:b2:75:d1',
      'VNI': '6796'}]
    >>> raw_data = ''
    >>> horizontal_parser.parse(raw_data)
    []
    """

    @staticmethod
    def parse(text, skip_head=None, skip_tail=None, header_keys=None, field_marker=None, data_split_size=1,
              token_length=0):
        """
        calling the get_parsed_data function will return a hash array while
        each array entry is a hash, based on above sample, the return data will be:
        [
          {VNI=6796, IP=192.168.139.11, MAC=00:50:...6e, Connection-ID=1},
          ...
          {VNI=6796, IP=192.168.139.201, MAC=00;50:..d1, Connection-ID=3}
        ]
        @param text: 
        @param skip_head: 
        @param skip_tail: 
        @param header_keys: 
        @param field_marker: 
        @param data_split_size: 
        @param token_length: 
        @return:
        """
        data = []
        lines = text.strip().split("\n")
        if ((len(lines) > 0) and ((lines[0].upper().find("ERROR") > 0) or
                                  (lines[0].upper().find("NOT FOUND") > 0) or
                                  (len(lines) == 1 and lines[0] == ""))):
            return data

        header_index = 0
        if skip_head:
            header_index = skip_head
        if header_index >= len(lines):
            py_logger.debug("Tried to get header of table at line number: %s, but there are only %s lines. Returning an"
                            " empty table, but check your parsing logic." % (header_index + 1, len(lines)))
            return data

        tail_index = len(lines)
        if skip_tail:
            tail_index = tail_index - skip_tail

        if not field_marker:
            field_marker = "\\s+"
        for line in lines[header_index:tail_index]:
            if line.strip() != "":
                elements = []
                if data_split_size == 1:
                    line = re.sub(field_marker, " ", line.strip())
                    elements = re.split(" ", line)
                elif data_split_size == 2:
                    for token in re.split("  ", line.strip()):
                        if len(token) > 0 and not token.startswith("---"):
                            elements.append(token.strip())
                if len(elements) > token_length:
                    data.append(elements)

        table = data

        if header_keys:
            header = header_keys
        else:
            header = table[0]
            del table[0]

        py_dicts = []
        for line in table:
            pydict = {}
            for i in range(0, len(header)):
                pydict.update({header[i]: line[i]})
            py_dicts.append(pydict)
        return py_dicts


if __name__ == '__main__':
    import doctest
    doctest.testmod()
