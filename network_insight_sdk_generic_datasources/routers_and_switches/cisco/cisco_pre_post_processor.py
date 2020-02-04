# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re

from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.common.utilities import merge_dictionaries
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor
from network_insight_sdk_generic_datasources.parsers.common.block_parser import SimpleBlockParser
from network_insight_sdk_generic_datasources.parsers.text.text_processor import rule_match_callback
from network_insight_sdk_generic_datasources.parsers.text.text_processor import Rule
from network_insight_sdk_generic_datasources.parsers.text.text_processor import TextProcessor
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser

NAME_KEY = 'name'
MTU_KEY = 'mtu'
IP_KEY = 'ipAddress'
IF_SPEED_KEY = 'interfaceSpeed'
ADMIN_ST_KEY = 'administrativeStatus'
OP_ST_KEY = 'operationalStatus'
HW_KEY = 'hardwareAddress'
DUPLEX_KEY = 'duplex'
OP_SPEED_KEY = 'operationalSpeed'
ACTIVE_PORTS_KEY = 'activePorts'
PASSIVE_PORTS_KEY = 'passivePorts'
VLAN_KEY = 'vlan'
CONNECTED_KEY = 'connected'
SW_PORT_KEY = 'switchPortMode'
VRF_KEY = 'vrf'

class CiscoDevicePrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        output_lines = []
        block_parser = SimpleBlockParser()
        blocks = block_parser.parse(data)
        for block in blocks:
            lines = block.splitlines()
            if len(lines) == 0:
                continue

            if 'Hardware' == lines[0]:
                self.parse_hardware_block(output_lines, lines)
            if 'Device name' in lines[0]:
                output_lines.append('name: {}'.format(lines[0].split(' ')[-1]))
                output_lines.append('hostname: {}'.format(lines[0].split(' ')[-1]))
        output_lines.append('os: NXOS')
        output_lines.append('vendor: Cisco')
        output_lines.append('haState: ACTIVE')
        return '\n'.join(output_lines)

    def post_process(self, data):
        return [merge_dictionaries(data)]

    @staticmethod
    def parse_hardware_block(output_lines, lines):
        for i in range(len(lines)):
            if i == 1:
                output_lines.append('model: ' + lines[i].split(' ')[1])
            if 'Processor Board ID' in lines[i]:
                output_lines.append('serial: {}'.format(lines[i].split(' ')[-1]))

class CiscoASRXRDeviceInfoPrePostProcessor(PrePostProcessor):

    def parse(self, data):
        py_logger.info("Parsing output \n{}".format(data))
        output_lines = []
        d = dict()
        lines = data.splitlines()
        for line in lines:
            if 'board' in line:
                d['serial'] = line.split(' ')[-1]
            if 'uptime' in line:
                d['name'] = line.split(' ')[0]
                d['hostname'] = line.split(' ')[0]
            if 'Software' in line:
                d['model'] = 'ASR9000'
        d['os'] = 'IOS XR'
        d['vendor'] = 'Cisco'
        d['haState'] = 'ACTIVE'
        output_lines.append(d)
        return output_lines

class CiscoASRXRInterfacesPrePostProcessor(PrePostProcessor):
    def parse(self, data):

        name_regex = "(.*) is (administratively )?(up|down), .*"
        mtu_regex = "MTU (\\d+) bytes.*"
        ip_regex = "Internet address is (.*)"
        interface_speed_regex = ".* BW (\\d+) .*"
        operational_speed_regex = ".*uplex.*, (.*)Mb/s"
        administrative_status_regex = ".* is (?:administratively )?(up|down), .*"
        operational_status_regex = ".* line protocol is (up|down)"
        hardware_address_regex = ".* address is (\\w+\\.\\w+\\.\\w+) .*"
        duplex_regex = "(.*)-(d|D)uplex.*"
        vlan_regex = "Encapsulation 802\\.1Q Virtual LAN, Vlan Id\\s+(\\d+).*"
        active_regex = '(.*).*Active'
        passive_regex = '(.*).*Passive'

        parser = TextProcessor(LineBasedBlockParser('line protocol'))
        parser.add_rule(Rule(NAME_KEY, name_regex, rule_match_callback))
        parser.add_rule(Rule(MTU_KEY, mtu_regex, rule_match_callback))
        parser.add_rule(Rule(IP_KEY, ip_regex, rule_match_callback))
        parser.add_rule(Rule(IF_SPEED_KEY, interface_speed_regex, rule_match_callback))
        parser.add_rule(Rule(OP_SPEED_KEY, operational_speed_regex, rule_match_callback))
        parser.add_rule(Rule(ADMIN_ST_KEY, administrative_status_regex, rule_match_callback))
        parser.add_rule(Rule(OP_ST_KEY, operational_status_regex, rule_match_callback))
        parser.add_rule(Rule(HW_KEY, hardware_address_regex, rule_match_callback))
        parser.add_rule(Rule(DUPLEX_KEY, duplex_regex, rule_match_callback))
        parser.add_rule(Rule(VLAN_KEY, vlan_regex, rule_match_callback))
        parser.add_rule(Rule(ACTIVE_PORTS_KEY, active_regex, rule_match_callback))
        parser.add_rule(Rule(PASSIVE_PORTS_KEY, passive_regex, rule_match_callback))
        output_lines = parser.process(data)
        if not bool(output_lines):
            return []

        for r in output_lines:
            py_logger.info("Processing row {}".format(r))
            r.update(duplex=r[DUPLEX_KEY].upper())
            if r[IF_SPEED_KEY] == '':
                r[IF_SPEED_KEY] = '0'
            r.update(interfaceSpeed=int(r[IF_SPEED_KEY]) * 1024)
            if r[OP_SPEED_KEY] == '':
                r[OP_SPEED_KEY] = '0'
            if r[IP_KEY].lower() == 'unknown':
                r[IP_KEY] = ''
            r.update(operationalSpeed=int(r[OP_SPEED_KEY]))
            r.update(administrativeStatus=r[ADMIN_ST_KEY].upper())
            r.update(operationalStatus=r[OP_ST_KEY].upper())
            r.update(connected="TRUE" if r[ADMIN_ST_KEY] == 'UP' else "FALSE")
            r.update(switchPortMode="ACCESS")
        return output_lines


class CiscoASRXRVRFRIPrePostProcessor(PrePostProcessor):
    def parse(self, data):
        output_lines = []
        lines = data.splitlines()
        for i in range(3, len(lines)):
            fields = lines[i].split()
            interfaceName = fields[0]
            vrf = fields[4]
            output_lines.append(dict({NAME_KEY: interfaceName, VRF_KEY: vrf}))
        return output_lines

class CiscoASRXRRouterInterfacesPrePostProcessor(PrePostProcessor):
    def process_tables(self, tables):
        interfaces_all = tables['showInterfacesAll']
        vrf_ri = tables['showVRFRI']
        output_lines = []
        for r in interfaces_all:
            py_logger.info("Processing row {}".format(r))
            if len(r[IP_KEY]) == 0:
                continue
            d = {}
            for v in vrf_ri:
                if r[NAME_KEY] in v[NAME_KEY]:
                    d.update(vrf=v[VRF_KEY])
            if VRF_KEY not in d:
                py_logger.warn('Ignoring row {}'.format(r))
                continue
            d.update(name=r[NAME_KEY])
            d.update(ipAddress=r[IP_KEY])
            d.update(vlan=r[VLAN_KEY])
            d.update(administrativeStatus=r[ADMIN_ST_KEY])
            d.update(operationalStatus=r[OP_ST_KEY])
            d.update(hardwareAddress=r[HW_KEY])
            d.update(mtu=str(r[MTU_KEY]))
            d.update(interfaceSpeed=str(r[IF_SPEED_KEY]))
            d.update(operationalSpeed=str(r[OP_SPEED_KEY]))
            d.update(duplex=r[DUPLEX_KEY].upper())
            d.update(connected=r[CONNECTED_KEY])
            d.update(switchPortMode=r[SW_PORT_KEY])
            output_lines.append(d)
        return output_lines

class CiscoASRXRSwitchPortsPrePostProcessor(PrePostProcessor):
    def process_tables(self, tables):
        interfaces_all = tables['showInterfacesAll']
        output_lines = []
        for r in interfaces_all:
            py_logger.info("Processing row {}".format(r))
            if len(r[IP_KEY]) > 0:
                py_logger.warn('Ignoring row {}'.format(r))
                continue
            if len(r[ACTIVE_PORTS_KEY]) > 0 or len(r[PASSIVE_PORTS_KEY]) > 0:
                py_logger.warn('Ignoring row {}'.format(r))
                continue
            value = r[VLAN_KEY]
            d = {}
            d.update(name=r[NAME_KEY])
            d.update(accessVlan=value)
            d.update(vlans='' if value.strip() == '' else ','.join([value]))
            d.update(administrativeStatus=r[ADMIN_ST_KEY])
            d.update(operationalStatus=r[OP_ST_KEY])
            d.update(hardwareAddress=r[HW_KEY])
            d.update(mtu=str(r[MTU_KEY]))
            d.update(interfaceSpeed=str(r[IF_SPEED_KEY]))
            d.update(operationalSpeed=str(r[OP_SPEED_KEY]))
            d.update(duplex=r[DUPLEX_KEY].upper())
            d.update(connected=r[CONNECTED_KEY])
            d.update(switchPortMode=r[SW_PORT_KEY])
            output_lines.append(d)
        return output_lines

class CiscoASRRXRPortChannelsPrePostProcessor(PrePostProcessor):
    def process_tables(self, tables):
        interfaces_all = tables['showInterfacesAll']
        output_lines = []
        for r in interfaces_all:
            py_logger.info("Processing row {}".format(r))
            if len(r[ACTIVE_PORTS_KEY]) == 0 and len(r[PASSIVE_PORTS_KEY]) == 0:
                continue
            value = r[VLAN_KEY]
            d = {}
            d.update(name=r[NAME_KEY])
            if value == '':
                d.update(vlans='' if value.strip() == '' else str(value))
            else:
                d.update(vlans='1' if r[NAME_KEY].find('.') == -1 else r[NAME_KEY][r[NAME_KEY].find('.') + 1:])
            d.update(administrativeStatus=r[ADMIN_ST_KEY])
            d.update(operationalStatus=r[OP_ST_KEY])
            d.update(hardwareAddress=r[HW_KEY])
            d.update(mtu=str(r[MTU_KEY]))
            d.update(interfaceSpeed=str(r[IF_SPEED_KEY]))
            d.update(operationalSpeed=str(r[OP_SPEED_KEY]))
            d.update(duplex=r[DUPLEX_KEY].upper())
            d.update(connected=r[CONNECTED_KEY])
            d.update(switchPortMode=r[SW_PORT_KEY])
            d.update(activePorts=r[ACTIVE_PORTS_KEY])
            d.update(passivePorts=r[PASSIVE_PORTS_KEY])
            output_lines.append(d)
        return output_lines

class CiscoASRXRVRFPrePostProcessor(PrePostProcessor):
    def parse(self, data):
        output_lines = [dict(name='default')]
        lines = data.splitlines()
        for i in range(2, len(lines)):
            fields = lines[i].split()
            vrf = fields[0]
            if len(vrf) == 0:
                continue
            output_lines.append(dict(name=vrf))
        return output_lines

class CiscoRoutePrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        output_lines = []
        lines = data.splitlines()
        vrf = None
        if 'IP Route Table for VRF' in lines[0]:
            vrf = lines[0].split(' ')[-1].replace('"', '')

        for i in range(5, len(lines)):
            line = lines[i]
            if 'denotes' in line:
                continue
            if 'via' in line:
                output_lines[-1] = output_lines[-1] + ' ' + line
                continue
            output_lines.append(line)

        if len(output_lines) == 0:
            return ''

        for i in range(0, len(output_lines)):
            line = output_lines[i]
            import re
            regex = "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,3}).*via (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}), (\\w+), .*, (static|direct|local)"
            compiled_regex = re.compile(regex)
            match = compiled_regex.match(line)
            groups = match.groups()
            name = groups[0]
            network = groups[0]
            nextHop = 'DIRECT' if 'direct' in groups[1].lower() else groups[1]
            interfaceName = groups[2]
            routeType = groups[3]
            output_lines[i] = "{}\t{}\t{}\t{}\t{}\t{}".format(name, network, nextHop, interfaceName, routeType, vrf)

        return '\n'.join(output_lines)


class CiscoRouterInterfacePrePostProcessor(PrePostProcessor):
    def post_process(self, data):
        result = []
        for d in data:
            if 'line protocol' in d['name']:
                d['name'] = d['name'].split()[0]
            if 'ipAddress' in d and len(d['ipAddress']) > 0:
                result = [d]
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
            if 'duplex' in d:
                if d['duplex'] == 'half':
                    d['duplex'] = 'HALF'
                elif d['duplex'] == 'full':
                    d['duplex'] = 'FULL'
                else:
                    d['duplex'] = 'OTHER'
        return result


class CiscoSwitchPortPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        result = []
        for d in data:
            if 'line protocol' in d['name']:
                d['name'] = d['name'].split()[0]
            if 'ipAddress' not in d:
                result = [d]
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
        return result


class CiscoPortChannelPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
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
            if 'switchPortMode' not in d:
                d['switchPortMode'] = 'OTHER'
            if 'switchPortMode' in d:
                if d['switchPortMode'] == 'access':
                    d['switchPortMode'] = 'ACCESS'
                elif d['switchPortMode'] == 'trunk':
                    d['switchPortMode'] = 'TRUNK'
                elif d['switchPortMode'] == 'fex':
                    d['switchPortMode'] = 'OTHER'
            if 'activePorts' in d:
                d['activePorts'] = d['activePorts'].replace('Eth', 'Ethernet').replace(' ', '')
            result = [d]
        return result


class CiscoRouterInterfaceVrfPrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        output_lines = []
        lines = data.splitlines()
        vrf = None
        if 'Interface Status' in lines[0]:
            vrf = lines[0].split(' ')[-1].replace('"', '')

        for i in range(1, len(lines)):
            interface_name = lines[i].split(' ')[0].replace(',', '')
            output_lines.append('{} {}'.format(interface_name, vrf))
        return '' if len(output_lines) == 0 else '\n'.join(output_lines)


class CiscoInterfaceVlanPrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        output_lines = []
        lines = data.splitlines()
        for i in range(len(lines)):
            line = str(lines[i])
            pattern = re.compile('\-+\s?')
            if pattern.match(line):
                continue
            if len(line) == 0:
                continue
            if line[0] == ' ':
                # Comma separated ports
                output_lines[-1] = output_lines[-1].replace(', ', ',') + ',' + line.strip().replace(', ', ',')
            else:
                output_lines.append(line)
        return '\n'.join(output_lines)

    def post_process(self, data):
        result = []
        port_vlan_dict = {}
        for d in data:
            vlan = d['vlan']
            ports = d['ports'].split(',')
            for port in ports:
                if port not in port_vlan_dict:
                    port_vlan_dict[port] = list()
                if port_vlan_dict[port] is None:
                    port_vlan_dict[port] = list()
                vlan_list = port_vlan_dict[port]
                vlan_list.append(vlan)
                port_vlan_dict[port] = vlan_list
        for k in port_vlan_dict.keys():
            vlans = ','.join(port_vlan_dict[k])
            result.append({'port': k, 'vlans': vlans})
        return result
