# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


import functools
import re
import traceback
from collections import defaultdict

from netaddr import IPAddress, IPNetwork

from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser
from network_insight_sdk_generic_datasources.parsers.common.line_parser import LineTokenizer
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor
from network_insight_sdk_generic_datasources.parsers.text.table_processor import TableProcessor


class ArubaPartialRoutesParser3810(PrePostProcessor):
    """
    Get routes from show route detail
    """
    def parse(self, data):
        """
        Parse show route instance detail command output
        :param data: show route detail command output
        :return: List of dict of routes
        """
        try:
            result = []
            header_regex = "(Destination)\\s+Gateway\\s+(VLAN Type)\\s+(Sub-Type)\\s+(Metric)\\s+(Dist.)"
            tokenizer = LineTokenizer()
            lines = data.splitlines()
            pattern = re.compile(header_regex)
            line_counter = 0
            header_found = False
            for line in lines:
                match = pattern.match(line.strip())
                if match is not None:
                    header_found = True
                if not header_found:
                    line_counter = 0
                line_counter = line_counter + 1
                is_start_of_output = header_found and line_counter > 3
                if not is_start_of_output:
                    continue
                # Parsing Logic goes here
                tokens = tokenizer.tokenize(line)
                routes = dict()
                routes.update({"vrf": "default"})
                network_match = tokens[0]
                ip_match_text = re.match("\\s+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}\\s+(.{16}).*", line)
                type_match_text = re.match("\\s+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}\\s+.{21}(.{10})", line)
                if ip_match_text:
                    next_hop_name = ip_match_text.group(1).strip()
                if type_match_text:
                    type_name = type_match_text.group(1).strip()
                if network_match is not None:
                    routes.update({"network": network_match})
                    routes.update({"name": network_match})
                    pass
                if next_hop_name is not None:
                    routes.update({"nextHop": next_hop_name})
                    pass
                if type_name is not None:
                    routes.update({"routeType": type_name})
                    pass
                result.append(routes.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
        return result


class Aruba3810MacAddressPrePostProcessor(PrePostProcessor):
    def post_process(self, data):
        result = []
        intfdetails = dict()
        for d in data:
            if 'vlan' in d:
                intfdetails.update({"vlan": d['vlan']})
            if 'port' in d:
                intfdetails.update({"port": d['port']})
            if 'macAddress' in d:
                d['macAddress'] = re.findall('..', d['macAddress'].replace('-', ''))
                d['macAddress'] = (":".join(d['macAddress']))
                intfdetails.update({"macAddress": d['macAddress']})
            result.append(intfdetails.copy())
        return result


class ArubaSwitchPorts2Parser3810(object):
    """
    Get interfaces from show interface status
    """
    def parse(self, data):
        """
        Parse show interface statusl command output
        :param data: show interface status
        :return: switch ports: name, vlan, speed, duplex mode, switchport mode
        """
        try:
            result = []
            header_regex = "(Port)\\s+Name\\s+(Status)\\s+(Config-mode)\\s+(Speed)\\s+(Type)\\s+(Tagged)\\s+(Untagged)"
            tokenizer = LineTokenizer()
            lines = data.splitlines()
            pattern = re.compile(header_regex)
            line_counter = 0
            header_found = False
            for line in lines:
                match = pattern.match(line.strip())
                if match is not None:
                    header_found = True
                if not header_found:
                    line_counter = 0
                line_counter = line_counter + 1
                is_start_of_output = header_found and line_counter > 3
                if not is_start_of_output:
                    continue
                # Parsing Logic goes here
                if len(line.strip()) == 0:
                    continue
                tokens = tokenizer.tokenize(line.strip())
                ports = dict()
                for token in tokens:
                    name_match = re.match("\\d{1,2}\\/.{1,2}", token)
                    duplex_match = re.match("(Auto|Full|half)", token)
                    operationalspeed_match = re.match("(100FDx|1000FDx|10GigFD)", token)
                    interfacespeed_match = re.match("(100/1000T|10GbE-GEN)", token)
                    switchportmode_match = re.match("(No|multi)", token)
                    vlan_match = re.match("^\\d{1,4}$", token)
                    if name_match is not None:
                        ports.update({"name": token})
                    elif duplex_match is not None:
                        ports.update({"duplex": token.upper()})
                    elif interfacespeed_match is not None:
                        if token == "100/1000T":
                            ports.update({"interfaceSpeed": "1000000000"})
                        elif token == "10GbE-GEN":
                            ports.update({"interfaceSpeed": "10000000000"})
                    elif operationalspeed_match is not None:
                        if token == "100FDx":
                            ports.update({"operationalSpeed": "100000000"})
                        elif token == "1000FDx":
                            ports.update({"operationalSpeed":  "1000000000"})
                        elif token == "10GigFD":
                            ports.update({"operationalSpeed":  "10000000000"})
                    elif switchportmode_match is not None:
                        if token == "No":
                            ports.update({"switchPortMode": "ACCESS"})
                        elif token == "multi":
                            ports.update({"switchPortMode": "TRUNK"})
                    elif vlan_match is not None:
                        if token != "1":
                            ports.update({"vlans": token})
                result.append(ports.copy())
        except Exception as e:
            py_logger.error("Line:[{}]\n{}\n{}".format(line, e, traceback.format_exc()))
            raise e
        return result


class ArubaLacp3810Parser(PrePostProcessor):
    """
    Parse Show LACP command
    """
    def parse(self, data):
        try:
            result = []
            header_regex = "(Port)\\s+Enabled\\s+(Group)\\s+(Status)\\s+(Partner)\\s+(Status)\\s+(Key)\\s+(Key)"
            tokenizer = LineTokenizer()
            lines = data.splitlines()
            pattern = re.compile(header_regex)
            line_counter = 0
            header_found = False
            for line in lines:
                match = pattern.match(line.strip())
                if match is not None:
                    header_found = True
                if not header_found:
                    line_counter = 0
                line_counter = line_counter + 1
                is_start_of_output = header_found and line_counter > 3
                if not is_start_of_output:
                    continue
                tokens = tokenizer.tokenize(line.strip())
                lacpPorts = dict()
                PortId = tokens[0]
                LacpEnabled_status = tokens[1]
                TrunkGroup = tokens[2]
                if PortId is not None:
                    lacpPorts.update({"portId" : PortId})
                if LacpEnabled_status is not None:
                    lacpPorts.update({"enabledStatus" : LacpEnabled_status})
                if TrunkGroup is not None:
                    lacpPorts.update({"trunkGroup" : TrunkGroup})
                result.append(lacpPorts.copy())
        except Exception as e:
            py_logger.error("Line:[{}]\n{}\n{}".format(line, e, traceback.format_exc()))
            raise e
        return result


class ArubaInterfaceStatusParser3810(PrePostProcessor):
    """
    Get routes from show route detail
    """
    def parse(self, data):
        """
        Parse show route instance detail command output
        :param data: show route detail command output
        :return: List of dict of routes
        """
        try:
            result = []

        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class ArubaInterfacePrePostParser3810(PrePostProcessor):
    def post_process(self, data):
            result = []
            intfdetails = dict()
            for d in data:
                if 'name' in d:
                    intfdetails.update({"name": d['name']})
                if 'administrativeStatus' in d:
                    d['administrativeStatus'] = 'UP' if d['administrativeStatus'] == 'Yes' else 'DOWN'
                    intfdetails.update({"administrativeStatus": d['administrativeStatus']})
                if 'operationalStatus' in d:
                    d['operationalStatus'] = 'UP' if d['operationalStatus'] == 'Up' else 'DOWN'
                    intfdetails.update({"operationalStatus": d['operationalStatus']})
                if 'connected' in d:
                    d['connected'] = 'UP' if d['connected'] == 'Up' else 'DOWN'
                    intfdetails.update({"connected": d['connected']})
                if 'hardwareAddress' in d:
                    d['hardwareAddress'] = re.findall('..', d['hardwareAddress'].replace('-', ''))
                    d['hardwareAddress'] = (":".join(d['hardwareAddress']))
                    intfdetails.update({"hardwareAddress": d['hardwareAddress']})
                result.append(intfdetails.copy())
            return result


class ArubaSwitchPortsAllDetailsPrePostParser8320(PrePostProcessor):
    def post_process(self, data):
        result = []
        for d in data:
            py_logger.info("Processing block {}".format(d))
            intfdetails = dict()
            if 'intname' in d:
                if d['intname'] == '' and d['aggname'] == '':
                    continue
                if d['intname'] != '':
                    intfdetails.update({"intname": d['intname']})
            if 'aggname' in d:
                if d['aggname'] != '':
                    intfdetails.update({"aggname": d['aggname']})
            if 'administrativeStatus' in d:
                intfdetails.update({"administrativeStatus": d['administrativeStatus'].upper()})
            if 'operationalStatus' in d:
                intfdetails.update({"operationalStatus": d['operationalStatus'].upper()})
            if 'connected' in d:
                intfdetails.update({"connected": d['connected'].upper()})
            if 'hardwareAddress' in d:
                intfdetails.update({"hardwareAddress": d['hardwareAddress']})
            if 'macAddress' in d:
                intfdetails.update({"macAddress": d['macAddress']})
            if 'interfaceSpeed' in d:
                intspeed = d['interfaceSpeed']
                if intspeed == '0':
                    intfdetails.update({'interfaceSpeed': intspeed})
                if intspeed != '':
                    intspeed = int(intspeed) * 100000
                    intfdetails.update({'interfaceSpeed': intspeed})
            if 'operationalSpeed' in d:
                opspeed = d['operationalSpeed']
                if opspeed == '0':
                    intfdetails.update({'operationalSpeed': opspeed})
                if opspeed != '':
                    opspeed = int(opspeed) * 100000
                    intfdetails.update({'operationalSpeed': opspeed})
            if 'switchPortMode' in d:
                    intfdetails.update({"switchPortMode": d['switchPortMode']})
            if 'switchPortMode' in d:
                if d['switchPortMode'] == 'access':
                    intfdetails.update({"switchPortMode": 'ACCESS'})
                if d['switchPortMode'] == 'native-untagged' or 'native-tagged':
                    intfdetails.update({"switchPortMode": 'TRUNK'})
                elif d['switchPortMode'] == 'access':
                    intfdetails.update({"switchPortMode": 'ACCESS'})
                else:
                    intfdetails.update({"switchPortMode": 'OTHER'})
            if 'activePorts' in d:
                ports = d['activePorts']
                intfdetails.update({"activePorts": ports.split()})
            if 'mtu' in d:
                intfdetails.update({"mtu": d['mtu']})
            if 'vlans' in d:
                if d['vlans'] == 'all':
                    intfdetails.update({'vlans': "1-4095"})
                else:
                    vlanslist = d['vlans'].split(',')
                    intfdetails.update({'vlans': vlanslist })
            result.append(intfdetails.copy())
        return result

class ArubaRoutePrePostParser8320(PrePostProcessor):
    def post_process(self, data):
            result = []
            routedetails = dict()
            for d in data:
                if 'name' in d:
                    if d['name'] == '':
                        continue
                    routedetails.update({"name": d['name']})
                if 'network' in d:
                    routedetails.update({"network": d['network']})
                if 'nextHop' in d:
                    name_match = re.match("(\\d+.\\d+.\\d+.\\d+)", d['nextHop'])
                    if not name_match:
                        routedetails.update({"nextHop": 'Direct'})
                    else:
                        routedetails.update({"nextHop": d['nextHop']})
                if 'routeType' in d:
                    routedetails.update({"routeType": d['routeType']})
                if 'interfaceName' in d:
                    routedetails.update({"interfaceName": d['interfaceName']})
                if 'vrf' in d:
                    routedetails.update({"vrf": d['vrf']})
                result.append(routedetails.copy())
            return result


class ArubaRouterInterfacePrePostProcessor3810(PrePostProcessor):
    def post_process(self, data):
            result = []
            intfdetails = dict()
            for d in data:
                if d['name'] != "vlan 1" and d['ipAddress'] != "":
                    if 'name' in d:
                        d['name'] = d['name'].replace(' ', '')
                        intfdetails.update({"name": d['name']})
                    if 'ipAddress' in d:
                        ipAddress_cidr = d['ipAddress'] + '/' + str(IPAddress(d['netmask']).netmask_bits())
                        intfdetails.update({"ipAddress": ipAddress_cidr})
                    intfdetails.update({"vrf": "default"})
                    intfdetails.update({"administrativeStatus": "UP"})
                    intfdetails.update({"operationalStatus": "UP"})
                    intfdetails.update({"connected": "TRUE"})
                    result.append(intfdetails.copy())
            return result


class ArubaVLANTrunkPrePostProcessor3810(PrePostProcessor):
    def post_process(self, data):
            preprocessedresult = []
            intfdetails = dict()
            for d in data:
                if d['trunkport'] != '':
                    intfdetails.update({"trunkport": d["trunkport"]})
                    if 'vlan' in d:
                        d['vlan'] = int(d['vlan'].replace(' ', ''))
                        intfdetails.update({"vlan": d['vlan']})
                else:
                    continue
                preprocessedresult.append(intfdetails.copy())

            def combine(def_dict, next_item):
                def_dict[next_item["trunkport"]].append(next_item["vlan"])
                return def_dict

            trunk_items = functools.reduce(combine, preprocessedresult, defaultdict(list))
            result = [{k:v} for k,v in trunk_items.items()]
            return result


class Aruba3810PortChannelTableProcessor(TableProcessor):
    def process_tables(self, tables):
        filtered_trunk_ports = list(filter(lambda port: ('Trk' in port['name']), tables['showSwitchPorts1']))
        lacp_members = tables['showLacp']
        trunk_vlan_mapping = tables['showRunVlan']
        d = dict()
        for port in filtered_trunk_ports:
            t = port
            t['activePorts'] = []
            t['passivePorts'] = []
            for member in lacp_members:
                if member['trunkGroup'] == port['name'] and member['enabledStatus'] == 'Active':
                    t['activePorts'].append(member['portId'])
                if member['trunkGroup'] == port['name'] and member['enabledStatus'] == 'Passive':
                    t['activePorts'].append(member['portId'])
            for vlanmap in trunk_vlan_mapping:
                key = list(dict.keys(vlanmap))
                trunkname = key[0]
                values = list(dict.values(vlanmap))
                vlans = values[0]
                if trunkname == t['name']:
                    t.update({"vlans": vlans})
            d.update(t)
            result = d
            return(result)


class Aruba3810RoutesTableProcessor(TableProcessor):
    def process_tables(self, tables):
        result = []
        routes = tables['routes']
        vlans = tables['vlan']
        for detail in routes:
            t = dict()
            if 'vrf' in detail:
                t.update({"vrf": detail['vrf']})
            if 'network' in detail:
                t.update({"network": detail['network']})
            if 'name' in detail:
                t.update({"name": detail['name']})
            if 'nextHop' in detail:
                nexthop = detail['nextHop']
                nexthop_ipmatch = re.match("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}", nexthop)
                t.update({"nextHop": detail['nextHop']})
            if 'routeType' in detail:
                t.update({"routeType": detail['routeType']})
                if detail['routeType'] == 'connected':
                    t.update({'interface': detail['nextHop']})
                if detail['routeType'] == 'static' and nexthop_ipmatch == None:
                    t.update({'interface': detail['nextHop']})
            for ipaddress in vlans:
                if 'interface' in t:
                    break
                network = ipaddress['ipAddress']
                if nexthop in IPNetwork(network):
                    t.update({'interface': ipaddress['name']})
                    break
            result.append(t.copy())
        return(result)


class Aruba8320InterfaceTableProcessor(TableProcessor):
    def parse(self, data):
        line_pattern = '.+for\\s+VRF\\s+".+"'
        parser = LineBasedBlockParser(line_pattern)
        blocks = parser.parse(data)
        result = []
        for block in blocks:
            t = dict()
            if block == '':
                continue
            match = re.match('.+for\\s+VRF\\s+"(.*)"', block)
            vrf = match.group(1)
            lines = block.splitlines()
            for line in lines:
                if line == '':
                    continue
                skip1 = re.match('.+for\\s+VRF\\s+"(.*)"', line)
                skip2 = re.match("Interface\\s+IP\\sAddress\\s+Interface\\sStatus", line)
                skip3 = re.match('link/admin', line)
                if any([skip1, skip2, skip3]):
                    continue
                itemmatch = re.match('(^.{1,16}[^ ])\\s+(.{1,25}[^ ])\\s+(.*)/(.*)', line)
                t.update({'vrf': vrf})
                t.update({'name': itemmatch.group(1)})
                if itemmatch.group(2) == 'No Address':
                    t.update({'ipAddress': ''})
                else:
                    t.update({'ipAddress': itemmatch.group(2)})
                t.update({'operationalStatus': itemmatch.group(3).upper()})
                t.update({'administrativeStatus': itemmatch.group(4).upper()})
                if itemmatch.group(3) == 'up':
                    t.update({'connected': 'TRUE'})
                else:
                    t.update({'connected': 'FALSE'})
                result.append(t.copy())
        return result


class ArubaVrfPrePostParser8320(PrePostProcessor):
    def post_process(self, data):
            vrfdetails = dict()
            for d in data:
                if d['name'] != '':
                    vrfdetails.update({"name": d["name"]})
            result = vrfdetails
            return result


class Aruba8320RouterInterfaceTableProcessor(TableProcessor):
    def process_tables(self, tables):
        allPorts = tables['allPorts']
        ri_vrf_mapping = tables['ri_vrf_mapping']
        result = []
        for t in ri_vrf_mapping:
            for port in allPorts:
                if port['intname'] == t['name']:
                    if 'hardwareAddress' in port:
                        t.update({'hardwareAddress': port['hardwareAddress']})
                    if 'interfaceSpeed' in port:
                        t.update({'interfaceSpeed': port['interfaceSpeed']})
                    if 'operationalSpeed' in port:
                        t.update({'operationalSpeed': port['operationalSpeed']})
                    break
            result.append(t.copy())
        return result


class Aruba8320SwitchPortTableProcessor(TableProcessor):
    def process_tables(self, tables):
        all_ports = tables['allPorts']
        result = []
        for port in all_ports:
            if 'intname' not in port:
                continue
            if port['intname'] == '':
                continue
            vlanmatch = re.match('vlan.*', port['intname'])
            if vlanmatch:
                continue
            loopbackmatch = re.match('loopback.*', port['intname'])
            if loopbackmatch:
                continue
            else:
                t = port.copy()
                t.pop('activePorts')
                t.pop('macAddress')
                result.append(t.copy())
        return result


class Aruba8320PortChannelTableProcessor(TableProcessor):
    def process_tables(self, tables):
        allPorts = tables['allPorts']
        result = []
        for port in allPorts:
            if 'aggname' not in port:
                continue
            else:
                t = port.copy()
                t.update({'hardwareAddress': t['macAddress']})
                t.pop('macAddress')
                result.append(t.copy())
        return result
