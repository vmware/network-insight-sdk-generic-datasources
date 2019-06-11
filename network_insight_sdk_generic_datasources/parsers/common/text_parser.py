from network_insight_sdk_generic_datasources.parsers.text.text_processor import TextProcessor
from network_insight_sdk_generic_datasources.parsers.text.text_processor import Rule
from network_insight_sdk_generic_datasources.parsers.text.text_processor import rule_match_callback


class GenericTextParser(object):

    @staticmethod
    def parse(text, rules=None):
        if rules is None:
            rules = {}
        tp = TextProcessor()
        for k in rules:
            tp.add_rule(Rule(k, rules[k], rule_match_callback))

        result = tp.process(text)
        if len(result) == 0:
            return ''
        d = {x: y for r in result for x, y in r.items()}
        return [d]
