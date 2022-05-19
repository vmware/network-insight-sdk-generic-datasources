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


class ExtremeSwitchPort2Parser(PrePostProcessor):
    """
    Get port number, duplex, operational speed, and switchport mode
    """
    def parse(self, data):
        """
        Parse show interface detail command output
        :param data: show interface gigabitEthernet name
        :return: List of dict of switch ports
        """
        try:
            result = []
            header_regex = "NUM\\s+NAME\\s+DESCRIPTION\\s+STATUS\\s+DUPLEX\\s+SPEED\\s+VLAN"
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
                if line == '':
                    continue
                # Parsing Logic goes here
                tokens = tokenizer.tokenize(line)
                if tokens is None or len(tokens) == 0:
                    continue
                switch_ports = dict()
                name = tokens[0]
                switch_ports.update({'name': name})
                for token in tokens:
                    operational_speed_match = re.match("^\\d+$", token)
                    duplex_match = re.match('half|full|auto', token)
                    vlan_match = re.match('Tagged|Access', token)
                    if not operational_speed_match and not duplex_match and not vlan_match:
                        continue
                    if operational_speed_match:
                        if token == 0:
                            switch_ports.update({'operationalSpeed': 0})
                        else:
                            operational_speed = int(token) * 8 * 1000000
                            switch_ports.update({'operationalSpeed': operational_speed})
                    if duplex_match:
                        switch_ports.update({'duplex': token.upper()})
                    if vlan_match:
                        if token == 'Access':
                            switch_ports.update({'switchPortMode': 'ACCESS'})
                        elif token == 'Tagged':
                            switch_ports.update({'switchPortMode': 'TRUNK'})
                        else:
                            switch_ports.update({'switchPortMode': 'OTHER'})
                result.append(switch_ports.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
        return result

class ExtremeRouterInterfacePrePostProcessor(PrePostProcessor):
    """
    Get port number, duplex, operational speed, and switchport mode
    """
    def parse(self, data):
        """
        Parse show interface detail command output
        :param data: show interface gigabitEthernet name
        :return: List of dict of switch interface_details
        """
        try:
            result = []
            router_interface1 = []
            router_interface2 = []
            header_regex = "ID\\s+NAME\\s+ADDRESS\\s+MASK\\s+FORMAT\\s+MAXSIZE\\s+WHEN_DOWN\\s+BROADCAST"
            second_table_regex = "MULTID\\s+IFINDEX\\s+PORTS\\s+ADMIN\\s+OPER"
            break_regex_count = 0
            tokenizer = LineTokenizer()
            lines = data.splitlines()
            pattern = re.compile(header_regex)
            line_counter = 0
            header_found = False
            for line in lines:
                if line == '':
                    continue
                match = pattern.match(line.strip())
                break_regex = re.match("All\\s+\\d+\\s+out\\s+of\\s+\\d+\\s+Total\\sNum\\sof\\sVlan\\sIp\\sEntries\\sdisplayed", line)
                if break_regex:
                    line_counter = -1
                    break_regex_count += 1
                    if break_regex_count == 2:
                        break
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
                if tokens is None or len(tokens) == 0:
                    continue
                interface_details = dict()
                if break_regex_count == 0:
                    ipaddress_cidr= tokens[2] + '/' + str(IPAddress(tokens[3]).netmask_bits())
                    interface_details.update({'name': tokens[2], 'vlan': tokens[0], 'ipAddress': ipaddress_cidr, 'mtu': tokens[5], 'administrativeStatus': 'UP', 'operationalStatus': 'UP', 'connected': 'UP'})
                    router_interface1.append(interface_details.copy())
                if break_regex_count == 1:
                    interface_details.update({'vlan': tokens[0], 'vrf': tokens[1]})
                    router_interface2.append(interface_details.copy())
            for interface in router_interface1:
                t = dict()
                t.update(interface)
                for item in router_interface2:
                    if item['vlan'] == interface['vlan']:
                        t.update({'vrf': item['vrf']})
                        break
                result.append(t.copy())
            return result
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
        return result

class ExtremeMacAddressTablePrePostProcessor(PrePostProcessor):
    def post_process(self, data):
        ###Need to validate SMLT Remote Interfaces???###
        result = []
        macDetails = dict()
        for d in data:
            if 'vlan' in d:
                macDetails.update({"vlan": d['vlan']})
            if 'macAddress' in d:
                macDetails.update({"macAddress": d['macAddress']})
            if 'switchPort' in d:
                portMatch = re.match('Port-(.*)', d['switchPort'])
                if portMatch:
                    port = portMatch.group(0)
                    macDetails.update({"port": port})
            result.append(macDetails.copy())
        return result

class ExtremePortChannelParser(PrePostProcessor):
    """
    Get port number, duplex, operational speed, and switchport mode
    """
    def parse(self, data):
        """
        Parse show interface detail command output
        :param data: show interface gigabitEthernet name
        :return: List of dict of switch ports
        """
        try:
            result = []
            port_channel1 = []
            port_channel2 = []
            header_regex = "MLTID\\s+IFINDEX\\s+NAME\\s+TYPE\\s+ADMIN\\s+CURRENT\\s+MEMBERS\\s+IDS"
            second_table_regex = "MULTID\\s+IFINDEX\\s+PORTS\\s+ADMIN\\s+OPER"
            break_regex_count = 0
            tokenizer = LineTokenizer()
            lines = data.splitlines()
            pattern = re.compile(header_regex)
            line_counter = 0
            header_found = False
            for line in lines:
                if line == '':
                    continue
                match = pattern.match(line.strip())
                break_regex = re.match("All\\s+\\d+\\s+out\\s+of\\s+\\d+\\s+Total\\sNum\\sof\\smlt\\sdisplayed", line)
                if break_regex:
                    line_counter = -1
                    break_regex_count += 1
                    if break_regex_count == 2:
                        break
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
                if tokens is None or len(tokens) == 0:
                    continue
                ports = dict()
                if break_regex_count == 0:
                    ports.update({'mltid': tokens[0], 'name': tokens[2], 'switchPortMode': tokens[3].upper()})
                    port_channel1.append(ports.copy())
                if break_regex_count == 1:
                    ports.update({'mltid': tokens[0], 'operationalStatus': tokens[4].upper()})
                    if tokens[3] == 'enable':
                        ports.update({'administrativeStatus': 'UP'})
                    else:
                        ports.update({'administrativeStatus': 'DOWN'})
                    port_channel2.append(ports.copy())
            for port in port_channel1:
                t = dict()
                t.update(port)
                for item in port_channel2:
                    if item['mltid'] == port['mltid']:
                        t.update({'operationalStatus': item['operationalStatus'], 'administrativeStatus': item['administrativeStatus']})
                        break
                t.pop('mltid')
                if t['operationalStatus'] == 'UP':
                    t.update({'connected': 'TRUE'})
                else:
                    t.update({'connected': 'FALSE'})
                result.append(t.copy())
            return result
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
        return result

class ExtremeRoutesPrePostProcessor(PrePostProcessor):
    def post_process(self, data):
        result = []
        routes = dict()
        for d in data:
            if 'name' in d:
                routes.update({"name": d['name']})
            if 'network' in d:
                ipaddress_cidr= d['name'] + '/' + str(IPAddress(d['network']).netmask_bits())
                routes.update({'network': ipaddress_cidr})
            if 'nextHop' in d:
                routes.update({'nextHop': d['nextHop']})
            if 'routeType' in d:
                if d['routeType'] == 'STAT':
                    routes.update({'routeType': 'Static'})
                if d['routeType'] == 'LOC':
                    routes.update({'routeType': 'DIRECT'})
                if d['routeType'] != 'STAT' and d['routeType'] != 'LOC':
                    routes.update({'routeType': d['routeType']})
            if 'interfaceName' in d:
                routes.update({'interfaceName': d['interfaceName']})
            if 'vrf' in d:
                if d['vrf'] == '-':
                    routes.update({'vrf': 'DEFAULT'})
                else:
                    routes.update({'vrf': d['vrf']})
            result.append(routes.copy())
        return result


#
# class ArubaPartialRoutesParser3810(PrePostProcessor):
#     """
#     Get routes from show route detail
#     """
#     def parse(self, data):
#         """
#         Parse show route instance detail command output
#         :param data: show route detail command output
#         :return: List of dict of routes
#         """
#         try:
#             result = []
#             header_regex = "(Destination)\\s+Gateway\\s+(VLAN Type)\\s+(Sub-Type)\\s+(Metric)\\s+(Dist.)"
#             tokenizer = LineTokenizer()
#             lines = data.splitlines()
#             pattern = re.compile(header_regex)
#             line_counter = 0
#             header_found = False
#             for line in lines:
#                 if line.strip() == '':
#                     continue
#                 match = pattern.match(line.strip())
#                 if match is not None:
#                     header_found = True
#                 if not header_found:
#                     line_counter = 0
#                 line_counter = line_counter + 1
#                 is_start_of_output = header_found and line_counter > 3
#                 if not is_start_of_output:
#                     continue
#                 # Parsing Logic goes here
#                 tokens = tokenizer.tokenize(line)
#                 routes = dict()
#                 routes.update({"vrf": "default"})
#                 network_match = tokens[0]
#                 ip_match_text = re.match("\\s+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}\\s+(.{16}).*", line)
#                 type_match_text = re.match("\\s+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}\\s+.{21}(.{10})", line)
#                 if ip_match_text:
#                     next_hop_name = ip_match_text.group(1).strip()
#                 if type_match_text:
#                     type_name = type_match_text.group(1).strip()
#                 if network_match is not None:
#                     routes.update({"network": network_match})
#                     routes.update({"name": network_match})
#                     pass
#                 if next_hop_name is not None:
#                     routes.update({"nextHop": next_hop_name})
#                     pass
#                 if type_name is not None:
#                     routes.update({"routeType": type_name})
#                     pass
#                 result.append(routes.copy())
#         except Exception as e:
#             py_logger.error("{}\n{}".format(e, traceback.format_exc()))
#         return result
#
#
# class Aruba3810RouterInterfaceParser(PrePostProcessor):
#     """
#     Get router interface, subnet and mask information
#     """
#     def parse(self, data):
#         """
#         Parse show ip instance detail command output
#         :param data: show ip detail command output
#         :return: List of dict of router interfaces
#         """
#         try:
#             result = []
#             header_regex = "VLAN\\s+.\\s+IP\\s+Config\\s+IP\\s+Address\\s+Subnet\\s+Mask\\s+Std\\s+Local"
#             tokenizer = LineTokenizer()
#             lines = data.splitlines()
#             pattern = re.compile(header_regex)
#             line_counter = 0
#             header_found = False
#             for line in lines:
#                 match = pattern.match(line.strip())
#                 if match is not None:
#                     header_found = True
#                 if not header_found:
#                     line_counter = 0
#                 line_counter = line_counter + 1
#                 is_start_of_output = header_found and line_counter > 3
#                 if not is_start_of_output:
#                     continue
#                 # Parsing Logic goes here
#                 tokens = tokenizer.tokenize(line)
#                 if tokens is None or len(tokens) == 0:
#                     continue
#                 vlan_interface = dict()
#                 vlan_match = tokens[0]
#                 ip_match_text = re.match(".+\\s+(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})\\s+\\d.+", line)
#                 mask_match = re.match(".+\\d\\s+(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}).+", line)
#                 if ip_match_text is None:
#                     continue
#                 if ip_match_text:
#                     ip_address = ip_match_text.group(1).strip()
#                     subnet_mask = mask_match.group(1).strip()
#                     ip_address_cidr = ip_address + '/' + str(IPAddress(subnet_mask).netmask_bits())
#                     vlan_interface.update({"name": vlan_match})
#                     vlan_interface.update({"ipAddress": ip_address_cidr})
#                     vlan_interface.update({"vrf": "default"})
#                     vlan_interface.update({"administrativeStatus": "UP"})
#                     vlan_interface.update({"operationalStatus": "UP"})
#                     vlan_interface.update({"connected": "TRUE"})
#                 result.append(vlan_interface.copy())
#         except Exception as e:
#             py_logger.error("{}\n{}".format(e, traceback.format_exc()))
#         return result
#
#
# class Aruba3810MacAddressPrePostProcessor(PrePostProcessor):
#     def post_process(self, data):
#         result = []
#         interface_details = dict()
#         for d in data:
#             if 'vlan' in d:
#                 interface_details.update({"vlan": d['vlan']})
#             if 'port' in d:
#                 interface_details.update({"port": d['port']})
#             if 'macAddress' in d:
#                 d['macAddress'] = re.findall('..', d['macAddress'].replace('-', ''))
#                 d['macAddress'] = (":".join(d['macAddress']))
#                 interface_details.update({"macAddress": d['macAddress']})
#             result.append(interface_details.copy())
#         return result
#
#
# class Aruba3810DefaultVrfsParser(PrePostProcessor):
#     def parse(self, data):
#         result = [{"name": 'default'}]
#         return result
#
#
# class ArubaSwitchPorts2Parser3810(object):
#     """
#     Get interfaces from show interface status
#     """
#     def parse(self, data):
#         """
#         Parse show interface status command output
#         :param data: show interface status
#         :return: switch ports: name, vlan, speed, duplex mode, switch port mode
#         """
#         try:
#             result = []
#             header_regex = "(Port)\\s+Name\\s+(Status)\\s+(Config-mode)\\s+(Speed)\\s+(Type)\\s+(Tagged)\\s+(Untagged)"
#             tokenizer = LineTokenizer()
#             lines = data.splitlines()
#             pattern = re.compile(header_regex)
#             line_counter = 0
#             header_found = False
#             for line in lines:
#                 match = pattern.match(line.strip())
#                 if match is not None:
#                     header_found = True
#                 if not header_found:
#                     line_counter = 0
#                 line_counter = line_counter + 1
#                 is_start_of_output = header_found and line_counter > 3
#                 if not is_start_of_output:
#                     continue
#                 # Parsing Logic goes here
#                 if len(line.strip()) == 0:
#                     continue
#                 tokens = tokenizer.tokenize(line.strip())
#                 ports = dict()
#                 for token in tokens:
#                     name_match = re.match("\\d{1,2}\\/.{1,2}", token)
#                     duplex_match = re.match("(Auto|Full|half)", token)
#                     status_match = re.match("(Up|Down)", token)
#                     operational_speed_match = re.match("(100FDx|1000FDx|10GigFD)", token)
#                     interface_speed_match = re.match("(100/1000T|10GbE-GEN)", token)
#                     switch_port_mode_match = re.match("(No|multi)", token)
#                     vlan_match = re.match("^\\d{1,4}$", token)
#                     if name_match is not None:
#                         name = re.match("\\d{1,2}\\/.{1,2}", token).group(0)
#                         ports.update({"name": name})
#                     elif duplex_match is not None:
#                         ports.update({"duplex": token.upper()})
#                     elif interface_speed_match is not None:
#                         if token == "100/1000T":
#                             ports.update({"interfaceSpeed": "1000000000"})
#                         elif token == "10GbE-GEN":
#                             ports.update({"interfaceSpeed": "10000000000"})
#                     elif operational_speed_match is not None:
#                         if token == "100FDx":
#                             ports.update({"operationalSpeed": "100000000"})
#                         elif token == "1000FDx":
#                             ports.update({"operationalSpeed":  "1000000000"})
#                         elif token == "10GigFD":
#                             ports.update({"operationalSpeed":  "10000000000"})
#                     elif switch_port_mode_match is not None:
#                         if token == "No":
#                             ports.update({"switchPortMode": "ACCESS"})
#                         elif token == "multi":
#                             ports.update({"switchPortMode": "TRUNK"})
#                     elif vlan_match is not None:
#                         if token != "1":
#                             ports.update({"vlans": token})
#                     elif status_match is not None:
#                         if token == "Up":
#                             ports.update({"administrativeStatus": "UP"})
#                             ports.update({"operationalStatus": "UP"})
#                         elif token == "Down":
#                             ports.update({"administrativeStatus": "DOWN"})
#                             ports.update({"operationalStatus": "DOWN"})
#                 result.append(ports.copy())
#         except Exception as e:
#             py_logger.error("Line:[{}]\n{}\n{}".format(line, e, traceback.format_exc()))
#             raise e
#         return result
#
# class ArubaRoutesParser8320v1007(object):
#     """
#     Get interfaces from show interface status
#     """
#     def parse(self, data):
#         """
#         Parse show interface status command output
#         :param data: show interface status
#         :return: switch ports: name, vlan, speed, duplex mode, switch port mode
#         """
#         try:
#             result = []
#             header_regex = "Type\\s+Metric"
#             tokenizer = LineTokenizer()
#             lines = data.splitlines()
#             pattern = re.compile(header_regex)
#             line_counter = 0
#             header_found = False
#             for line in lines:
#                 match = pattern.match(line.strip())
#                 if match is not None:
#                     header_found = True
#                 if not header_found:
#                     line_counter = 0
#                 line_counter = line_counter + 1
#                 is_start_of_output = header_found and line_counter > 3
#                 if not is_start_of_output:
#                     continue
#                 # Parsing Logic goes here
#                 if len(line.strip()) == 0:
#                     continue
#                 tokens = tokenizer.tokenize(line.strip())
#                 routes = dict()
#                 prefix_match = re.match("(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}\\/\\d{1,3})", tokens[0])
#                 if not prefix_match:
#                     continue
#                 next_hop_match = re.match("(\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})", tokens[1])
#                 vrf_match = re.match("(-)", tokens[3])
#                 ospf_match = re.match("(O)", tokens[4])
#                 bgp_match = re.match("(B)", tokens[4])
#                 rip_match = re.match("(R)", tokens[4])
#                 routes.update({"name": tokens[0]})
#                 routes.update({"network": tokens[0]})
#                 if next_hop_match is not None:
#                     routes.update({"nextHop": tokens[1]})
#                 else:
#                     routes.update({"nextHop": "DIRECT"})
#                 if tokens[4] == "C" or "L":
#                     routes.update({"routeType": "Direct"})
#                 if ospf_match is not None:
#                     routes.update({"routeType": "OSPF"})
#                 elif bgp_match is not None:
#                     routes.update({"routeType": "BGP"})
#                 elif rip_match is not None:
#                     routes.update({"routeType": "RIP"})
#                 if vrf_match is not None:
#                     routes.update({"vrf": "default"})
#                 else:
#                     routes.update({"vrf": tokens[3]})
#                 routes.update({"interfaceName": tokens[2]})
#                 result.append(routes.copy())
#         except Exception as e:
#             py_logger.error("Line:[{}]\n{}\n{}".format(line, e, traceback.format_exc()))
#             raise e
#         return result
#
# class ArubaLacp3810Parser(PrePostProcessor):
#     """
#     Parse Show LACP command
#     """
#     def parse(self, data):
#         try:
#             result = []
#             header_regex = "(Port)\\s+Enabled\\s+(Group)\\s+(Status)\\s+(Partner)\\s+(Status)\\s+(Key)\\s+(Key)"
#             tokenizer = LineTokenizer()
#             lines = data.splitlines()
#             pattern = re.compile(header_regex)
#             line_counter = 0
#             header_found = False
#             for line in lines:
#                 if line.strip() == '':
#                     continue
#                 match = pattern.match(line.strip())
#                 if match is not None:
#                     header_found = True
#                 if not header_found:
#                     line_counter = 0
#                 line_counter = line_counter + 1
#                 is_start_of_output = header_found and line_counter > 3
#                 if not is_start_of_output:
#                     continue
#                 tokens = tokenizer.tokenize(line.strip())
#                 link_ports = dict()
#                 port_id = tokens[0]
#                 link_enabled_status = tokens[1]
#                 trunk_group = tokens[2]
#                 if port_id is not None:
#                     link_ports.update({"portId": port_id})
#                 if link_enabled_status is not None:
#                     link_ports.update({"enabledStatus": link_enabled_status})
#                 if trunk_group is not None:
#                     link_ports.update({"trunkGroup": trunk_group})
#                 result.append(link_ports.copy())
#         except Exception as e:
#             py_logger.error("Line:[{}]\n{}\n{}".format(line, e, traceback.format_exc()))
#             raise e
#         return result
#
#
# class ArubaInterfaceStatusParser3810(PrePostProcessor):
#     """
#     Get routes from show route detail
#     """
#     def parse(self, data):
#         """
#         Parse show route instance detail command output
#         :param data: show route detail command output
#         :return: List of dict of routes
#         """
#         try:
#             result = []
#
#         except Exception as e:
#             py_logger.error("{}\n{}".format(e, traceback.format_exc()))
#             raise e
#         return result
#
#
# class ArubaInterfacePrePostParser3810(PrePostProcessor):
#     def post_process(self, data):
#         result = []
#         interface_details = dict()
#         for d in data:
#             if 'name' in d:
#                 interface_details.update({"name": d['name']})
#             if 'administrativeStatus' in d:
#                 d['administrativeStatus'] = 'UP' if d['administrativeStatus'] == 'Yes' else 'DOWN'
#                 interface_details.update({"administrativeStatus": d['administrativeStatus']})
#             if 'operationalStatus' in d:
#                 d['operationalStatus'] = 'UP' if d['operationalStatus'] == 'Up' else 'DOWN'
#                 interface_details.update({"operationalStatus": d['operationalStatus']})
#             if 'connected' in d:
#                 d['connected'] = 'TRUE' if d['connected'] == 'Up' else 'FALSE'
#                 interface_details.update({"connected": d['connected']})
#             if 'hardwareAddress' in d:
#                 d['hardwareAddress'] = re.findall('..', d['hardwareAddress'].replace('-', ''))
#                 d['hardwareAddress'] = (":".join(d['hardwareAddress']))
#                 interface_details.update({"hardwareAddress": d['hardwareAddress']})
#             result.append(interface_details.copy())
#         return result
#
#
# class ArubaSwitchPortsAllDetailsPrePostParser8320(PrePostProcessor):
#     def post_process(self, data):
#         result = []
#         for d in data:
#             py_logger.info("Processing block {}".format(d))
#             interface_details = dict()
#             if 'intname' in d:
#                 if d['intname'] == '' and d['aggname'] == '':
#                     continue
#                 if d['intname'] != '':
#                     interface_details.update({"intname": d['intname']})
#             if 'aggname' in d:
#                 if d['aggname'] != '':
#                     interface_details.update({"aggname": d['aggname']})
#             if 'administrativeStatus' in d:
#                 interface_details.update({"administrativeStatus": d['administrativeStatus'].upper()})
#             if 'operationalStatus' in d:
#                 interface_details.update({"operationalStatus": d['operationalStatus'].upper()})
#             if 'connected' in d:
#                 if d['connected'] == 'up':
#                     interface_details.update({"connected": "TRUE"})
#                 else:
#                     interface_details.update({"connected": "FALSE"})
#             if 'hardwareAddress' in d:
#                 interface_details.update({"hardwareAddress": d['hardwareAddress']})
#             if 'macAddress' in d:
#                 interface_details.update({"macAddress": d['macAddress']})
#             if 'interfaceSpeed' in d:
#                 intspeed = d['interfaceSpeed']
#                 if intspeed == '0':
#                     interface_details.update({'interfaceSpeed': intspeed})
#                 if intspeed != '':
#                     intspeed = int(intspeed) * 100000
#                     interface_details.update({'interfaceSpeed': intspeed})
#             if 'operationalSpeed' in d:
#                 opspeed = d['operationalSpeed']
#                 if opspeed == '0':
#                     interface_details.update({'operationalSpeed': opspeed})
#                 if opspeed != '':
#                     opspeed = int(opspeed) * 100000
#                     interface_details.update({'operationalSpeed': opspeed})
#             if 'switchPortMode' in d:
#                     interface_details.update({"switchPortMode": d['switchPortMode']})
#             if 'switchPortMode' in d:
#                 if d['switchPortMode'] == 'access':
#                     interface_details.update({"switchPortMode": 'ACCESS'})
#                 if d['switchPortMode'] == 'native-untagged' or 'native-tagged':
#                     interface_details.update({"switchPortMode": 'TRUNK'})
#                 elif d['switchPortMode'] == 'access':
#                     interface_details.update({"switchPortMode": 'ACCESS'})
#                 else:
#                     interface_details.update({"switchPortMode": 'OTHER'})
#             if 'activePorts' in d:
#                 ports = d['activePorts']
#                 ports = ports.split()
#                 portsstring = ",".join(ports)
#                 interface_details.update({"activePorts": portsstring})
#             if 'mtu' in d:
#                 interface_details.update({"mtu": d['mtu']})
#             if 'vlans' in d:
#                 if d['vlans'] == 'all':
#                     interface_details.update({'vlans': "1-4095"})
#                 else:
#                     vlanslist = d['vlans'].split(',')
#                     vlanstring = ",".join(vlanslist)
#                     interface_details.update({'vlans': vlanstring})
#             result.append(interface_details.copy())
#         return result
#
#
# # class ArubaRoutePrePostParser8320(PrePostProcessor):
# #     def post_process(self, data):
# #         result = []
# #         route_details = dict()
# #         for d in data:
# #             if 'name' in d:
# #                 if d['name'] == '':
# #                     continue
# #                 route_details.update({"name": d['name']})
# #             if 'network' in d:
# #                 route_details.update({"network": d['network']})
# #             if 'nextHop' in d:
# #                 name_match = re.match("(\\d+.\\d+.\\d+.\\d+)", d['nextHop'])
# #                 if not name_match:
# #                     route_details.update({"nextHop": 'DIRECT'})
# #                     route_details.update({"routeType": 'DIRECT'})
# #                 else:
# #                     route_details.update({"nextHop": d['nextHop']})
# #                     route_details.update({"routeType": d['routeType']})
# #             if 'interfaceName' in d:
# #                 route_details.update({"interfaceName": d['interfaceName']})
# #             if 'vrf' in d:
# #                 route_details.update({"vrf": d['vrf']})
# #             result.append(route_details.copy())
# #         return result
#
#
# class ArubaVLANTrunkPrePostProcessor3810(PrePostProcessor):
#     def post_process(self, data):
#         preprocessed_result = []
#         interface_details = dict()
#         for d in data:
#             if d['trunkport'] != '':
#                 interface_details.update({"trunkport": d["trunkport"]})
#                 if 'vlan' in d:
#                     d['vlan'] = int(d['vlan'].replace(' ', ''))
#                     interface_details.update({"vlan": d['vlan']})
#             else:
#                 continue
#             preprocessed_result.append(interface_details.copy())
#
#         def combine(def_dict, next_item):
#             def_dict[next_item["trunkport"]].append(next_item["vlan"])
#             return def_dict
#
#         trunk_items = functools.reduce(combine, preprocessed_result, defaultdict(list))
#         result = [{k: v} for k, v in trunk_items.items()]
#         return result
#
#
# class Aruba3810PortChannelTableProcessor(TableProcessor):
#     def process_tables(self, tables):
#         filtered_trunk_ports = list(filter(lambda port: ('Trk' in port['name']), tables['showSwitchPorts1']))
#         lacp_members = tables['showLacp']
#         result = []
#         d = dict()
#         for port in filtered_trunk_ports:
#             t = port
#             t.update({'switchPortMode': 'TRUNK'})
#             # t['activePorts'] = []
#             # t['passivePorts'] = []
#             # for member in lacp_members:
#             #     if member['trunkGroup'] == port['name'] and member['enabledStatus'] == 'Active':
#             #         t['activePorts'].append(member['portId'])
#             #     if member['trunkGroup'] == port['name'] and member['enabledStatus'] == 'Passive':
#             #         t['activePorts'].append(member['portId'])
#             d.update(t)
#             result.append(d)
#         return result
#
#
# class Aruba3810RoutesTableProcessor(TableProcessor):
#     def process_tables(self, tables):
#         result = []
#         routes = tables['routespart1']
#         vlans = tables['router-interfaces']
#         for detail in routes:
#             t = dict()
#             if 'vrf' in detail:
#                 t.update({"vrf": detail['vrf']})
#             if 'network' in detail:
#                 t.update({"network": detail['network']})
#             if 'name' in detail:
#                 t.update({"name": detail['name']})
#             if 'nextHop' in detail:
#                 next_hop = detail['nextHop']
#                 next_hop_text_match = re.match("\\D+", next_hop)
#                 next_hop_ip_match = re.match("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,2}", next_hop)
#                 if next_hop == 'reject':
#                     continue
#                 if next_hop_text_match:
#                     t.update({"nextHop": "DIRECT"})
#                 else:
#                     t.update({"nextHop": detail['nextHop']})
#             if 'routeType' in detail:
#                 if detail['routeType'] == 'connected':
#                     t.update({"routeType": "DIRECT"})
#                 else:
#                     t.update({"routeType": detail['routeType']})
#                 if detail['routeType'] == 'connected':
#                     if next_hop_text_match == None:
#                         t.update({'interface': detail['nextHop']})
#                     if next_hop_text_match:
#                         prefix = detail['nextHop'][:12]
#                         for row in vlans:
#                             if row['name'].startswith(prefix):
#                                 t.update({'interfaceName': row['name']})
#                             break
#                 if detail['routeType'] == 'static' and next_hop_ip_match == None:
#                     t.update({'interfaceName': detail['nextHop']})
#             for row in vlans:
#                 if 'interface' in t:
#                     break
#                 network = row['ipAddress']
#                 if next_hop_ip_match == None:
#                     continue
#                 if next_hop in IPNetwork(network):
#                     t.update({'interfaceName': row['name']})
#                     break
#             result.append(t.copy())
#         return result
#
#
# class Aruba8320InterfaceTableProcessor(TableProcessor):
#     def parse(self, data):
#         line_pattern = '.+for\\s+VRF\\s+".+"'
#         parser = LineBasedBlockParser(line_pattern)
#         blocks = parser.parse(data)
#         result = []
#         for block in blocks:
#             t = dict()
#             if block == '':
#                 continue
#             match = re.match('.+for\\s+VRF\\s+"(.*)"', block)
#             vrf = match.group(1)
#             lines = block.splitlines()
#             for line in lines:
#                 if line == '':
#                     continue
#                 skip1 = re.match('.+for\\s+VRF\\s+"(.*)"', line)
#                 skip2 = re.match("Interface\\s+IP\\sAddress\\s+Interface\\sStatus", line)
#                 skip3 = re.match('link/admin', line)
#                 if any([skip1, skip2, skip3]):
#                     continue
#                 item_match = re.match('(^.{1,16}[^ ])\\s+(.{1,25}[^ ])\\s+(.*)/(.*)', line)
#                 t.update({'vrf': vrf})
#                 t.update({'name': item_match.group(1)})
#                 if item_match.group(2) == 'No Address':
#                     continue
#                 else:
#                     t.update({'ipAddress': item_match.group(2)})
#                 t.update({'operationalStatus': item_match.group(3).upper()})
#                 t.update({'administrativeStatus': item_match.group(4).upper()})
#                 if item_match.group(3) == 'up':
#                     t.update({'connected': 'TRUE'})
#                 else:
#                     t.update({'connected': 'FALSE'})
#                 result.append(t.copy())
#         return result
#
#
# class ArubaVrfPrePostParser8320(PrePostProcessor):
#     def post_process(self, data):
#             vrf_details = dict()
#             for d in data:
#                 if d['name'] != '':
#                     vrf_details.update({"name": d["name"]})
#             result = vrf_details
#             return result
#
#
# class Aruba8320RouterInterfaceTableProcessor(TableProcessor):
#     def process_tables(self, tables):
#         allPorts = tables['allPorts']
#         ri_vrf_mapping = tables['ri_vrf_mapping']
#         result = []
#         for t in ri_vrf_mapping:
#             for port in allPorts:
#                 if port['intname'] == t['name']:
#                     if 'hardwareAddress' in port:
#                         t.update({'hardwareAddress': port['hardwareAddress']})
#                     if 'interfaceSpeed' in port:
#                         t.update({'interfaceSpeed': port['interfaceSpeed']})
#                     if 'operationalSpeed' in port:
#                         t.update({'operationalSpeed': port['operationalSpeed']})
#                     break
#             result.append(t.copy())
#         return result
#
#
# class Aruba8320SwitchPortTableProcessor(TableProcessor):
#     def process_tables(self, tables):
#         all_ports = tables['allPorts']
#         result = []
#         for port in all_ports:
#             if 'intname' not in port:
#                 continue
#             if port['intname'] == '':
#                 continue
#             vlan_match = re.match('vlan.*', port['intname'])
#             if vlan_match:
#                 continue
#             loopback_match = re.match('loopback.*', port['intname'])
#             if loopback_match:
#                 continue
#             else:
#                 t = port.copy()
#                 t.pop('activePorts')
#                 t.pop('macAddress')
#                 t['name'] = t.pop('intname')
#                 result.append(t.copy())
#         return result
#
#
# class Aruba8320PortChannelTableProcessor(TableProcessor):
#     def process_tables(self, tables):
#         allPorts = tables['allPorts']
#         result = []
#         for port in allPorts:
#             if 'aggname' not in port:
#                 continue
#             else:
#                 t = port.copy()
#                 t.update({'hardwareAddress': t['macAddress']})
#                 t.pop('macAddress')
#                 t['name'] = t.pop('aggname')
#                 result.append(t.copy())
#         return result
