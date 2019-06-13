# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import csv
from network_insight_sdk_generic_datasources.common.log import py_logger
import os


class CsvWriter(object):
    CSV_EXTENSION = '.csv'

    @staticmethod
    def write(path, filename, table):
        if table is None:
            py_logger.warn('Table cannot be None. Will not write to csv.')
            return
        if type(table) != list:
            py_logger.warn('Table is a list of dictionaries. Will not write to csv.')
            return
        if len(table) == 0:
            py_logger.warn('Table cannot be empty. Will not write to csv.')
            return
        csv.register_dialect('dialect',
                             quoting=csv.QUOTE_ALL,
                             skipinitialspace=True)
        if not os.path.exists(path):
            os.makedirs(path)
        if not os.path.exists(path):
            py_logger.error("Couldn't create directory {}. Please check permissions.".format(path))
            return
        with open(path + '/' + filename + CsvWriter.CSV_EXTENSION, 'w') as write_file:
            writer = csv.writer(write_file, dialect='dialect')
            if len(table) > 0:
                row = table[0]
                if type(row) != dict:
                    py_logger.warn('Table is a list of dictionaries. Not a valid row.')
                    return
                headers = row.keys()
                writer.writerow(headers)
                for d in table:
                    if type(d) != dict:
                        py_logger.warn('Not a valid row. Will skip row.')
                        continue
                    row = []
                    for h in headers:
                        row.append(d[h] if h in d else '')
                    writer.writerow(row)
