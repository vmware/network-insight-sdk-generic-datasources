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
from network_insight_sdk_generic_datasources.common.constants import REUSE_TABLES_KEY
from network_insight_sdk_generic_datasources.common.constants import COMMAND_FORMAT_KEY
from network_insight_sdk_generic_datasources.common.constants import REUSE_TABLES_FOR_COMMAND_KEY
from network_insight_sdk_generic_datasources.common.constants import REUSE_TABLE_PROCESSOR_KEY
from network_insight_sdk_generic_datasources.common.constants import REUSE_COLUMN_KEY
from network_insight_sdk_generic_datasources.common.constants import EXCEPT_COMMAND_KEY
from network_insight_sdk_generic_datasources.common.constants import EXCEPT_VALUE_KEY

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

    def __init__(self, device, model,  workloads, credentials, table_joiners, result_writer, generation_dir):
        self.device = device
        self.model = model
        self.workloads = workloads
        self.credentials = credentials
        self.table_joiners = table_joiners
        self.result_writer = result_writer
        self.generation_dir = generation_dir
        self.result_map = {}  # will be set only after executing commands

    def process(self):
        self.execute_commands()
        self.join_tables()
        self.write_results()

    def write_results(self):
        for table in self.result_writer[TABLE_ID_KEY]:
            csv_writer = CsvWriter()
            csv_writer.write(self.generation_dir, table, self.result_map[table])

    def join_tables(self):
        if not self.table_joiners:
            return
        try:
            for joiner_config in self.table_joiners:
                joiner_class = import_utilities.load_class(joiner_config[NAME_KEY])()
                source_table = self.result_map[joiner_config[SOURCE_TABLE_KEY]]
                destination_table = self.result_map[joiner_config[DESTINATION_TABLE_KEY]]
                source_column = joiner_config[SOURCE_COLUMN_KEY]
                destination_column = joiner_config[DESTINATION_COLUMN_KEY]
                table = import_utilities.load_class_method(joiner_class, 'join_tables')(source_table, destination_table,
                                                                                        source_column, destination_column)
                self.result_map[joiner_config[JOINED_TABLE_ID_KEY]] = table
        except KeyError as e:
            py_logger.error("Failed to join tables: KeyError : {}".format(e))
            raise e

    def execute_commands(self):
        ssh_connect_handler = None
        try:
            ssh_connect_handler = SSHConnectHandler(ip=self.credentials.ip_or_fqdn,
                                                    username=self.credentials.username,
                                                    password=self.credentials.password,
                                                    device_type=self.credentials.device_type,
                                                    port=self.credentials.port),
            command_output_dict = {}
            for workload in self.workloads:
                command_id = workload[TABLE_ID_KEY]
                py_logger.info("Processing workload {}".format(workload))
                if REUSE_TABLES_KEY in workload:
                    table = self.process_tables(workload)
                elif REUSE_COMMAND_KEY in workload:
                    command_result = command_output_dict[workload[REUSE_COMMAND_KEY]]
                    workload[COMMAND_KEY] = workload[REUSE_COMMAND_KEY]
                    py_logger.info('Command %s Result %s' % (workload[REUSE_COMMAND_KEY], command_result))
                    table = self.parse_command_output(workload, command_result)

                elif REUSE_TABLES_FOR_COMMAND_KEY in workload:
                    source_table = self.result_map[workload[REUSE_TABLES_FOR_COMMAND_KEY]]
                    if ARGUMENTS_KEY in workload:
                        reuse_column = workload[ARGUMENTS_KEY][REUSE_COLUMN_KEY]
                        command_format = workload[ARGUMENTS_KEY][COMMAND_FORMAT_KEY]
                        command_list = []
                        for row in source_table:
                            value = row.get(reuse_column)
                            if EXCEPT_VALUE_KEY in workload[ARGUMENTS_KEY] and value == workload[ARGUMENTS_KEY][EXCEPT_VALUE_KEY]:
                                command_list.append(workload[ARGUMENTS_KEY][EXCEPT_COMMAND_KEY])
                            else:
                                command_list.append(command_format.replace("()", value))
                        table = []
                        for command in command_list:
                            py_logger.error("Iterate through command list for Routes")
                            command_result = ssh_connect_handler.execute_command(command)
                            command_output_dict[command] = command_result
                            py_logger.info('Command %s Result %s' % (command, command_result))
                            table = table + self.parse_command_output(workload, command_result)

                    # table_key_list = import_utilities.get_list_of_table_key(source_table, )
                    #
                    # process_table = import_utilities.load_class_for_process_table(self.device, workload[REUSE_TABLES_FOR_COMMAND_KEY])
                    # tables = {}
                    # for table in workload[REUSE_TABLES_FOR_COMMAND_KEY].split(','):
                    #     tables[table] = self.result_map[table]
                    # result_dict = self.call_process_table_function(process_table, tables)
                    #
                    # command_result = command_output_dict[workload[REUSE_COMMAND_KEY]]  ## this will be list of VRFs
                    # input_to_cmd = convertToList(command_result)  ## write convertToList
                    # command_result = ''
                    # for input in input_to_cmd:
                    #     output = ssh_connect_handler.execute_command(
                    #         prepareCommand(input, command_format))  # command_format will be in your yaml definition
                    #     command_result = command_result + '\n\n' + output
                    # table = self.parse_command_output(workload, command_result)  # We already have this.

                else:
                    py_logger.info('Issuing Command %s' % (workload[COMMAND_KEY]))
                    command_result = ssh_connect_handler.execute_command(workload[COMMAND_KEY])
                    command_output_dict[workload[COMMAND_KEY]] = command_result
                    py_logger.info('Command %s Result %s' % (workload[COMMAND_KEY], command_result))
                    table = self.parse_command_output(workload, command_result)
                if 'switch' == command_id:
                    table[0]['ipAddress/fqdn'] = self.credentials.ip_or_fqdn
                    table[0]['name'] = "{}-{}".format(table[0]['name'], self.credentials.ip_or_fqdn)
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
        table = self.filter_columns(cmd, table)
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
        process_table = import_utilities.load_class_for_process_table(self.device, cmd[REUSE_TABLE_PROCESSOR_KEY])()
        tables = {}
        for table in cmd[REUSE_TABLES_KEY].split(','):
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
            pre_post_processor = import_utilities.load_class_for_pre_post_parser(self.device,
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