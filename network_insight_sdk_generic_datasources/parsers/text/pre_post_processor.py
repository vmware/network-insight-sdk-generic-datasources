# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


class PrePostProcessor(object):

    def pre_process(self, data):
        type(self)
        return data

    def post_process(self, data):
        type(self)
        return data

    def process_tables(self, tables):
        type(self)
        return tables


