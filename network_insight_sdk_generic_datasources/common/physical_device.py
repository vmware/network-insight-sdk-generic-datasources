# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


import network_insight_sdk_generic_datasources.common.import_module_utilities as import_utilities
from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.connection.ssh_connect_handler import SSHConnectHandler
from network_insight_sdk_generic_datasources.writers.csv_writer import CsvWriter

from network_insight_sdk_generic_datasources.common.constants import COMMAND_KEY
from network_insight_sdk_generic_datasources.common.constants import PARSER_KEY
from network_insight_sdk_generic_datasources.common.constants import BLOCK_PARSER_KEY
from network_insight_sdk_generic_datasources.common.constants import NAME_KEY
from network_insight_sdk_generic_datasources.common.constants import ARGUMENTS_KEY
from network_insight_sdk_generic_datasources.common.constants import PRE_POST_PROCESSOR_KEY
from network_insight_sdk_generic_datasources.common.constants import SELECT_COLUMNS_KEY
from network_insight_sdk_generic_datasources.common.constants import REUSE_COMMAND_KEY
from network_insight_sdk_generic_datasources.common.constants import TABLE_ID_KEY
from network_insight_sdk_generic_datasources.common.constants import REUSE_TABLE_KEY
from network_insight_sdk_generic_datasources.common.constants import PROCESS_TABLE_KEY


from network_insight_sdk_generic_datasources.common.constants import DESTINATION_COLUMN_KEY
from network_insight_sdk_generic_datasources.common.constants import SOURCE_COLUMN_KEY
from network_insight_sdk_generic_datasources.common.constants import DESTINATION_TABLE_KEY
from network_insight_sdk_generic_datasources.common.constants import SOURCE_TABLE_KEY
from network_insight_sdk_generic_datasources.common.constants import JOINED_TABLE_ID_KEY
from network_insight_sdk_generic_datasources.common.constants import PATH_KEY


class PhysicalDevice(object):
    """
    Handler for executing basic & mandatory logic for executing commands and directing output to a defined
    output format. For example, CSV for Excel.
    """

    def __init__(self, device, model,  command_list, credentials, table_joiners, result_writer):
        self.device = device
        self.model = model
        self.command_list = command_list
        self.credentials = credentials
        self.table_joiners = table_joiners
        self.result_writer = result_writer
        self.result_map = {}

    def process(self):
        self.execute_commands()
        self.join_tables()
        self.write_results()

    def write_results(self):
        for table in self.result_writer[TABLE_ID_KEY]:
            csv_writer = CsvWriter()
            for cmd in self.command_list:
                if cmd[TABLE_ID_KEY] == table:
                    result_map = self.filter_columns(cmd, self.result_map[table])
                    csv_writer.write(self.result_writer[PATH_KEY], table, result_map)
                    break

    def join_tables(self):
        if not self.table_joiners:
            return

        for joiner_config in self.table_joiners['table']:
            joiner_class = import_utilities.load_class(joiner_config[NAME_KEY])()
            source_table = self.result_map[joiner_config[SOURCE_TABLE_KEY]]
            destination_table = self.result_map[joiner_config[DESTINATION_TABLE_KEY]]
            source_column = joiner_config[SOURCE_COLUMN_KEY]
            destination_column = joiner_config[DESTINATION_COLUMN_KEY]
            table = import_utilities.load_class_method(joiner_class, 'join_tables')(source_table, destination_table,
                                                                                    source_column, destination_column)
            self.result_map[joiner_config[JOINED_TABLE_ID_KEY]] = table

    def execute_commands(self):
        ssh_connect_handler = None
        try:
            ssh_connect_handler = SSHConnectHandler(ip=self.credentials.ip_or_fqdn,
                                                    username=self.credentials.username,
                                                    password=self.credentials.password,
                                                    device_type=self.credentials.device_type)
            command_output_dict = {}
            for cmd in self.command_list:
                command_id = cmd[TABLE_ID_KEY]
                if REUSE_TABLE_KEY in cmd:
                    result_dict = self.process_tables(cmd)
                    if len(result_dict) > 0:
                        table = result_dict
                else:
                    if REUSE_COMMAND_KEY in cmd:
                        command_result = command_output_dict[cmd[REUSE_COMMAND_KEY]]
                        cmd[COMMAND_KEY] = cmd[REUSE_COMMAND_KEY]
                    else:
                        command_result = ssh_connect_handler.execute_command(cmd[COMMAND_KEY])
                        command_output_dict[cmd[COMMAND_KEY]] = command_result

                    py_logger.info('Command %s Result %s' % (cmd[COMMAND_KEY], command_result))
                    table = self.parse_command_output(cmd, command_result)

                self.result_map[command_id] = table
        except Exception as e:
            py_logger.error("Error occurred while executing command : {}".format(e))
            raise e
        finally:
             ssh_connect_handler.close_connection()

    def parse_command_output(self, cmd, command_result):
        blocks = []
        table = []  # Each row is dictionary
        if BLOCK_PARSER_KEY in cmd:
            if ARGUMENTS_KEY in cmd[BLOCK_PARSER_KEY]:
                block_parser = import_utilities.load_block_parser(cmd[BLOCK_PARSER_KEY][NAME_KEY])(
                    **cmd[BLOCK_PARSER_KEY][ARGUMENTS_KEY])
            else:
                block_parser = import_utilities.load_class(cmd[BLOCK_PARSER_KEY][NAME_KEY])()
            blocks = import_utilities.load_class_method(block_parser, 'parse')(command_result)

        else:
            blocks.append(command_result)
        for block in blocks:
            try:
                if not block: continue
                result_dict = self.process_block(block, cmd)
                if len(result_dict) > 0:
                    table += result_dict
            except IndexError as e:
                py_logger.info("Couldn't parse block {}\nfor command {}".format(block, cmd[COMMAND_KEY]))
                py_logger.error(e)
        return table

    @staticmethod
    def filter_columns(cmd, table):
        if SELECT_COLUMNS_KEY not in cmd:
            return table

        final_table = []
        keys = cmd[SELECT_COLUMNS_KEY]
        for row in table:
            new_row = {}
            for k in keys:
                try:
                    value = row[k]
                except KeyError:
                    py_logger.error("Did not find key {}".format(k))
                    continue
                new_row[keys[k]] = value
            final_table.append(new_row)
        return final_table

    def process_tables(self, cmd):
        process_table = import_utilities.load_device_process_table(self.device, cmd[PROCESS_TABLE_KEY])()
        tables = {}
        for table in cmd[REUSE_TABLE_KEY].split(','):
            tables[table] = self.result_map[table]
        result_dict = self.call_process_table_function(process_table, tables)

        message = 'Expecting result dictionary to be list of dictionaries'
        # Verify parsed objects
        if type(result_dict) != list:
            raise TypeError(message)
        if len(result_dict) > 0 and type(result_dict[0]) != dict:
            raise TypeError(message)
        return result_dict

    def process_block(self, block=None, cmd=None):

        # Calling pre processor
        has_pre_post_processor = PRE_POST_PROCESSOR_KEY in cmd[PARSER_KEY]
        if has_pre_post_processor:
            pre_post_processor = import_utilities.load_device_pre_post_parser(self.device,
                                                                              cmd[PARSER_KEY][PRE_POST_PROCESSOR_KEY])()
            block = self.call_pre_function(pre_post_processor, block)

        # Calling main parse function
        if ARGUMENTS_KEY in cmd[PARSER_KEY]:
            result_dict = import_utilities.load_class(cmd[PARSER_KEY][NAME_KEY])().parse(block, **cmd[PARSER_KEY][
                ARGUMENTS_KEY])
        else:
            result_dict = import_utilities.load_class(cmd[PARSER_KEY][NAME_KEY])().parse(block)

        # Calling post processor
        if has_pre_post_processor:
            result_dict = self.call_post_function(pre_post_processor, result_dict)
        message = 'Expecting result dictionary to be list of dictionaries'

        # Verify parsed objects
        if type(result_dict) != list:
            raise TypeError(message)
        if len(result_dict) > 0 and type(result_dict[0]) != dict:
            raise TypeError(message)
        return result_dict

    @staticmethod
    def call_pre_function(pre_post_processor, block):
        return import_utilities.load_class_method(pre_post_processor, 'pre_process')(block)

    @staticmethod
    def call_post_function(pre_post_processor, result_dict):
        return import_utilities.load_class_method(pre_post_processor, 'post_process')(result_dict)

    @staticmethod
    def call_process_table_function(process_table, result_dict):
        return import_utilities.load_class_method(process_table, 'process_tables')(result_dict)