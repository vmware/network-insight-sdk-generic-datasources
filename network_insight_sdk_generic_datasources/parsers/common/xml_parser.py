# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import re
from xml.etree import ElementTree


class XmlParser(object):
    """
    XML Output like below can be parsed with vertical table parser
    <chassis-module>\
            <part-number>123-456</part-number>\
            <serial-number>AA1234</serial-number>\
            <model-number>SRX600-PWR-645AC-POE</model-number>\
    </chassis-module>

    >>> from network_insight_sdk_generic_datasources.parsers.common.vertical_table_parser import VerticalTableParser
    >>> import pprint
    >>> text = '''<chassis-module>\
                    <part-number>123-456</part-number>\
                    <serial-number>AA1234</serial-number>\
                    <model-number>SRX600-PWR-645AC-POE</model-number>\
                    </chassis-module>'''
    >>> parser = XmlParser()
    >>> pprint.pprint(parser.parse(text))
    {'chassis-module': {'model-number': 'SRX600-PWR-645AC-POE',
                        'part-number': '123-456',
                        'serial-number': 'AA1234'}}
    """

    def parse(self, xml_str):
        """
        Calling the parse function will return list
        @param xml_str:
        @return:
        """
        pattern = ' xmlns="[^"]+"'
        count = len(re.findall(pattern, xml_str))
        xml_str = re.sub(pattern, '', xml_str, count=count)
        root = ElementTree.XML(xml_str)
        pydicts = ConvertXmlToDict(root)
        return [pydicts]


class XmlDictObject(dict):
    """
    Adds object like functionality to the standard dictionary.
    """

    def __init__(self, initdict=None):
        if initdict is None:
            initdict = {}
        dict.__init__(self, initdict)


def _ConvertXmlToDictRecurse(node, dictclass):
    nodedict = dictclass()

    if len(node.items()) > 0:
        # if we have attributes, set them
        nodedict.update(dict(node.items()))

    for child in node:
        # recursively add the element's children
        newitem = _ConvertXmlToDictRecurse(child, dictclass)
        if nodedict.has_key(child.tag):
            # found duplicate tag, force a list
            if type(nodedict[child.tag]) is type([]):
                # append to existing list
                nodedict[child.tag].append(newitem)
            else:
                # convert to list
                nodedict[child.tag] = [nodedict[child.tag], newitem]
        else:
            # only one, directly set the dictionary
            nodedict[child.tag] = newitem

    if node.text is None:
        text = ''
    else:
        text = node.text.strip()

    if len(nodedict) > 0:
        # if we have a dictionary add the text as a dictionary value (if there is any)
        if len(text) > 0:
            nodedict['_text'] = text
    else:
        # if we don't have child nodes or attributes, just set the text
        nodedict = text

    return nodedict


def ConvertXmlToDict(root, dictclass=XmlDictObject):
    """
    Converts an XML file or ElementTree Element to a dictionary
    """

    # If a string is passed in, try to open it as a file
    if not isinstance(root, ElementTree.Element):
        raise TypeError, 'Expected ElementTree.Element or file path string'

    return dictclass({root.tag: _ConvertXmlToDictRecurse(root, dictclass)})


if __name__ == '__main__':
    import doctest
    doctest.testmod()