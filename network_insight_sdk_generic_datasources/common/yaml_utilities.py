import os
import yaml


def altered_compose_document(self):
    self.get_event()
    node = self.compose_node(None, None)
    self.get_event()
    return node


yaml.SafeLoader.compose_document = altered_compose_document


# adapted from http://code.activestate.com/recipes/577613-yaml-include-support/
def yaml_include(loader, node):
    file_name = "{}{}{}".format(os.path.dirname(loader.name), os.sep, node.value)
    with open(file_name) as inputfile:
        return altered_safe_load(inputfile, master=loader)


yaml.add_constructor("!include", yaml_include, Loader=yaml.SafeLoader)


def altered_safe_load(stream, Loader=yaml.SafeLoader, master=None):
    loader = Loader(stream)
    if master is not None:
        loader.anchors = master.anchors
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()
