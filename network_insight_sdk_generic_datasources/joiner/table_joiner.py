# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from network_insight_sdk_generic_datasources.common.log import py_logger


class SimpleTableJoiner(object):

    def __init__(self):
        pass

    def join_tables(self, source_table, destination_table, source_column, destination_column):
        is_source_table_empty = source_table is None or len(source_table) == 0
        is_destination_table_empty = destination_table is None or len(destination_table) == 0

        if is_source_table_empty and is_destination_table_empty:
            py_logger.warn('source and destination table cannot be empty')
            return None
        if is_source_table_empty:
            py_logger.warn('source table is empty. Returning destination table')
            return destination_table
        if is_destination_table_empty:
            py_logger.warn('destination table is empty. Returning source table')
            return source_table

        source_key_value_row = {}
        for source_row in source_table:
            source_key_value_row[source_row[source_column]] = source_row

        destination_key_value_row = {}
        for destination_row in destination_table:
            destination_key_value_row[destination_row[destination_column]] = destination_row

        joined_table = []
        for key in destination_key_value_row:
            pydict = destination_key_value_row[key]
            if key not in source_key_value_row:
                self.fill_with_empty_values(pydict, source_key_value_row.values()[0], source_column)
            else:
                srow = source_key_value_row[key]
                for k in srow:
                    if k == source_column:
                        continue
                    pydict[k] = srow[k]
            pydict = self.update(pydict)
            joined_table += [pydict]

        return joined_table

    def update(self, row_dict):
        return row_dict

    @staticmethod
    def fill_with_empty_values(pydict, row_dict, source_column):
        for k in row_dict:
            if k == source_column:
                continue
            pydict[k] = ''
