# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from netmiko import ConnectHandler
from netmiko.ssh_dispatcher import CLASS_MAPPER_BASE, CLASS_MAPPER
from network_insight_sdk_generic_datasources.connection.device_type import DeviceType
from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.routers_and_switches.aruba.custom_aruba_ssh import CustomArubaSSH


class SSHConnectHandler(object):
    LINE_BREAK = '\nLINE_BREAK'

    def __init__(self, ip=None, username=None, password=None, device_type=None, port=22, **kwargs):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port

        if device_type not in DeviceType.values():
            raise ValueError("Invalid device type {}".format(device_type))

        self.device_type = DeviceType.value_of(device_type).to_lower_case()

        if self.device_type.lower() == 'aruba_os':
            CLASS_MAPPER[self.device_type] = CustomArubaSSH

        py_logger.info("Making connection to Device IP {} Type {} classMapperBase {} classMapper {}".format(ip, self.device_type, CLASS_MAPPER_BASE[self.device_type], CLASS_MAPPER[self.device_type]))
        self.net_connect = ConnectHandler(ip=ip, username=username, password=password, device_type=self.device_type, port=self.port)

    def execute_command(self, command=None):
        if command is None:
            raise ValueError("Command not provided")
        py_logger.info('Executing command <{}>'.format(command))
        result = self.net_connect.send_command(command, delay_factor=2, max_loops=1000)
        py_logger.info("Command output {}".format(result))
        return result

    def execute_multiple_commands(self, commands=None):
        if commands is None or len(commands) == 0:
            raise ValueError("Commands not provided")
        result = ''
        for command in commands:
            result = result + self.execute_command(command) + SSHConnectHandler.LINE_BREAK

    def close_connection(self):
        self.net_connect.disconnect()


if __name__ == '__main__':
    cisco_881 = {
        'device_type': 'CISCO_IOS',
        'ip_or_fqdn': '1.1.1.1',
        'username': 'admin',
        'password': 'admin'
    }

    sshConnectHandler = SSHConnectHandler(**cisco_881)
    interfaces = sshConnectHandler.execute_command('show int brief')
    sshConnectHandler.close_connection()
    py_logger.info(interfaces)
