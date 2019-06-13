# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


class SimpleTableJoiner(object):

    def __init__(self):
        pass

    def join_tables(self, source_table, destination_table, source_column, destination_column):
        if source_table is None:
            raise ValueError('source_table can be None')

        if destination_table is None:
            raise ValueError('destination_table can be None')

        if source_column is None:
            raise ValueError('source_column can be None')

        if destination_column is None:
            raise ValueError('destination_column can be None')

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
            joined_table += [pydict]

        return joined_table

    @staticmethod
    def fill_with_empty_values(pydict, row_dict, source_column):
        for k in row_dict:
            if k == source_column:
                continue
            pydict[k] = ''
