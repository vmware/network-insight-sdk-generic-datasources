# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


from functools import reduce


def merge_dictionaries(list_of_dictionaries):
    if list_of_dictionaries is None or list_of_dictionaries == []:
        return {}
    return reduce(lambda x, y: dict(x, **y), list_of_dictionaries)
