# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


import traceback
import re
from network_insight_sdk_generic_datasources.common.log import py_logger
from netaddr import IPAddress
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser
from network_insight_sdk_generic_datasources.parsers.common.text_parser import GenericTextParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import SimpleBlockParser


class DellSwitchPrePostProcessor(PrePostProcessor):
    """
    Get details of dell switch
    """
    def post_process(self, data):
        """
        Get details of dell switch
        :param data: Parsed output of show version command
        :return: list with dict containing DELL switch details
        """
        temp = data[0]
        temp['vendor'] = "DELL"
        temp['haState'] = "ACTIVE"
        return [temp]


class DellPortChannelPrePostParser(PrePostProcessor):
    """
    Get details of port channel
    """

    def parse(self, data):
        """
        Parse show interfaces port-channel command output to get port channel details
        :param data: show interfaces port-channel Command output
        :return: list of dict contains all port channels
        """
        result = []
        lines = data.splitlines()
        for d in lines:
            if d.startswith('Po'):
                d = d.split()
                if d[1].startswith("Active"):
                    active_ports = []
                    for p in d[2:]:
                        pattern = re.compile('Te\d+/\d+/\d+')
                        if pattern.match(p):
                            active_ports.append(p.replace(',', ''))
                result.append(dict(name=d[0],
                    connected="true",
                    administrativeStatus="UP",
                    operationalStatus="UP",
                    hardwareAddress="",
                    interfaceSpeed="",
                    operationalSpeed="",
                    mtu="",
                    duplex="OTHER",
                    switchPortMode="OTHER",
                    activePorts=','.join(active_ports),
                    passivePorts=''))
        return result


class DellLLDPRemoteDevicePrePostParser(PrePostProcessor):
    """
    Get lldp neighbours
    """
    def post_process(self, data):
        result = []
        for d in data:
            if 'Embedded' not in d['Chassis ID']:
                result.append(dict(localInterface=d['Interface'],
                                   remoteDevice=d['System Name'],
                                   remoteInterface=d['Port ID']))
        return result


class DellRoutesPrePostParser(PrePostProcessor):
    """
    Get routes from show ip route vrf command
    """
    route_rules = dict(nextHop=".* via (\\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\\b),.*",
                       interfaceName=".*:.*[m|s], (.*)",
                       interface_connected=".*connected, (.*)")

    rules = dict(network=".*\*(\\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\\b/.*)\[.*", routeType="(.*).*\*.*")

    route_types = dict(B="BGP", S="Static", C="DIRECT", O="OSPF")

    def parse(self, data):
        """
        Parse show ip route vrf command output
        :param data: show ip route vrf command output
        :return: List of dict of routes
        """
        try:
            result = []
            parser = LineBasedBlockParser(".*(\*).*")
            blocks = parser.parse(data)
            generic_parser = GenericTextParser()
            vrf = "master"

            for block in blocks[2:]:
                line_blocks = block.splitlines()
                route_network = generic_parser.parse(line_blocks[0], self.rules)[0]
                route_type = route_network['routeType'].rstrip()

                for idx, line_block in enumerate(line_blocks):
                    routes = generic_parser.parse(line_block, self.route_rules)[0]
                    routes.update({"network": "{}".format(route_network['network'])})
                    routes.update({"name": "{}_{}".format(route_network['network'], idx)})
                    routes.update({"vrf": vrf})
                    routes.update({"interfaceName": routes['interfaceName'].lstrip() if routes['interfaceName']
                                                                            else routes['interface_connected'].lstrip()})
                    routes.pop('interface_connected')
                    routes.update({"routeType": "{}".format(self.route_types[route_type]
                                                            if self.route_types.has_key(route_type) else "DIRECT")})
                    routes.update({"nextHop": "{}".format(routes['nextHop'] if routes['nextHop'] else "DIRECT")})
                    result.append(routes.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class DellIPInterfacesPrePostParser(PrePostProcessor):
    """
    Get router interface using show ip interfaces command
    """

    def post_process(self, data):
        """
        Parse show ip interfaces command output to get router interface
        :param data: show ip interfaces command output
        :return: List of dict of router interfaces
        """
        result = []
        for d in data:
            result.append(dict(interfaceSpeed='',
                               name=d['interface'],
                               vlan=d['interface'].replace('Vl', ''),
                               administrativeStatus=d['state'].lower(),
                               mtu='',
                               operationalStatus=d['state'].lower(),
                               connected='true',
                               vrf='default',
                               hardwareAddress='',
                               ipAddress=d['ipAddress'] + '/' + str(IPAddress(d['ipMask']).netmask_bits()),
                               operationalSpeed=''))
        return result


class DellSwitchPortPrePostProcessor(PrePostProcessor):
    """
    Get switch ports using show interfaces command
    """
    def post_process(self, data):
        """
        Parse show interfaces command output to get switch ports
        :param data: show interfaces command output
        :return: List of dict of switch ports
        """
        result = []
        for d in data:
            if 'line protocol' in d['name']:
                d['name'] = d['name'].split()[0]
            if 'duplex' in d:
                if d['duplex'] == 'half':
                    d['duplex'] = 'HALF'
                elif d['duplex'] == 'full':
                    d['duplex'] = 'FULL'
                else:
                    d['duplex'] = 'OTHER'
            if 'administrativeStatus' in d:
                if d['administrativeStatus'] == 'up':
                    d['administrativeStatus'] = 'UP'
                else:
                    d['administrativeStatus'] = 'DOWN'
            if 'operationalStatus' in d:
                if d['operationalStatus'] == 'up':
                    d['operationalStatus'] = 'UP'
                else:
                    d['operationalStatus'] = 'DOWN'
            if 'connected' in d:
                if d['connected'] == 'up':
                    d['connected'] = 'true'
                else:
                    d['connected'] = 'false'
            if 'switchPortMode' in d:
                if d['switchPortMode'] == 'access':
                    d['switchPortMode'] = 'ACCESS'
                elif d['switchPortMode'] == 'trunk':
                    d['switchPortMode'] = 'TRUNK'
                else:
                    d['switchPortMode'] = 'OTHER'
            result.append(d)
        return result
