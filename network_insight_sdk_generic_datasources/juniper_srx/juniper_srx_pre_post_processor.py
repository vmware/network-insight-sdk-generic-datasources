# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


import traceback

from network_insight_sdk_generic_datasources.common.utilities import merge_dictionaries
from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor
from network_insight_sdk_generic_datasources.parsers.common.block_parser import SimpleBlockParser
from network_insight_sdk_generic_datasources.parsers.common.text_parser import GenericTextParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser
from network_insight_sdk_generic_datasources.parsers.common.line_parser import LineTokenizer


class JuniperConfigInterfacesPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        result = []
        if data[0]['vlan']:
            result.append(data[0])
        return result


class JuniperDevicePrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        output_lines = []
        block_parser = SimpleBlockParser()
        blocks = block_parser.parse(data)
        for block in blocks:
            if 'node0' in block:
                lines = block.splitlines()
                output_lines.append('hostname: {}'.format(lines[2].split(' ')[-1]))
                output_lines.append('name: Juniper {}'.format(lines[3].split(' ')[-1]))
                output_lines.append('os: JUNOS {}'.format(lines[4].split(' ')[-1]))
                output_lines.append('model: {}'.format(lines[3].split(' ')[-1]))
        output_lines.append('ipAddress/fqdn: 10.40.13.37')
        output_lines.append('vendor: Juniper')
        return '\n'.join(output_lines)

    def post_process(self, data):
        return [merge_dictionaries(data)]


class JuniperVRFTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        result = []
        for vrf in tables['showVRFInterface']:
            temp = {}
            temp['name'] = vrf['name']
            result.append(temp)
        return result


class JuniperInterfaceParser():
    physical_regex_rule = dict(mtu=".*Link-level type: .*, MTU: (.*?),", name="Physical interface: (.*), Enabled.*",
                               hardwareAddress=".*Current address: .*, Hardware address: (.*)",
                               operationalStatus=".*, Enabled, Physical link is (.*)",
                               administrativeStatus="Physical interface: .*, (.*), Physical link is .*")

    logical_interface_regex = dict(name="Logical interface (.*) \(Index .*", ipAddress=".*Local: (.*), Broadcast:.*",
                                   mask=".*Destination: (.*), Local:.*, Broadcast:.*")


    def parse(self, data):
        try:
            result = []
            generic_parser = GenericTextParser()
            physical = generic_parser.parse(data, self.physical_regex_rule)[0]
            physical.update({'connected': "TRUE" if physical['operationalStatus'] == "Up" else "FALSE"})
            physical.update({'operationalStatus': "UP" if physical['operationalStatus'] == "Up" else "DOWN"})
            physical.update({'administrativeStatus': "UP" if physical['administrativeStatus'] == "Enabled" else "DOWN"})
            physical.update({'hardwareAddress': "" if physical['hardwareAddress'].isalpha() else physical['hardwareAddress']})
            if not physical['hardwareAddress']:
                return result

            parser = LineBasedBlockParser('Logical interface')
            blocks = parser.parse(data)
            for block in blocks:
                logical = generic_parser.parse(block, self.logical_interface_regex)[0]
                if logical['mask'] == "Unspecified":
                    continue
                if logical['ipAddress'] and logical['mask']:
                    physical.update({"ipAddress": "{}/{}".format(logical['ipAddress'], logical['mask'].split('/')[1])})
                else:
                    physical.update({"ipAddress": ""})
                physical.update({"members": "{}".format(self.get_members(block))})
                physical.update({"name": "{}".format(logical['name'] if logical['name'] else physical['name'])})
                result.append(physical.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
            raise e
        return result

    @staticmethod
    def get_members(block):
        result = ""
        got_members = False
        lines = []
        for i in block.splitlines():
            if "Link:" in i:
                lines = []
                continue
            if "Marker Statistics" in i or "LACP info:" in i:
                got_members = True
                break
            lines.append(i)
        if got_members:
            result = ",".join([mem for mem in lines if "Input" not in mem and "Output" not in mem])
        return result


class JuniperSwitchPortTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        result = []
        vlan_interface = ["{}.{}".format(i['interface'], i['unit']) for i in tables['showConfigInterface']]
        for port in tables['showInterface']:
            port["switchPortMode"] = "TRUNK" if port['name'] in vlan_interface else "ACCESS"
            port["vlans"] = port['name'].split('.')[1] if port['name'] in vlan_interface else "0"
            if port['ipAddress']: continue
            p = port.copy()
            p.pop('members')
            p.pop('ipAddress')
            result.append(p)
        return result


class JuniperRouterInterfaceTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        result = []
        for port in tables['showInterface']:
            port.update({"vrf": "{}".format(self.get_vrf(port, tables))})
            if port["ipAddress"]:
                p = port.copy()
                p['vlan'] = port['vlans']
                p.pop('members')
                p.pop('vlans')
                result.append(p)
        return result

    @staticmethod
    def get_vrf(port, tables):
        vrf_name = "master"
        for vrf in tables['showVRFInterface']:
            if port['name'] in vrf['interfaces']:
                return vrf['name']
        return vrf_name


class JuniperPortChannelTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        result = []
        for port in tables['showInterface']:
            if port['members']:
                p = port.copy()
                p.pop('members')
                p.pop('ipAddress')
                result.append(p)
        return result


class JuniperRoutesParser(PrePostProcessor):
    route_rules = dict(nextHop="Next hop: (.*) via", next_hop_type=".*Next hop type: (.*?), .*",
                               interfaceName=".* via (.*),", routeType="\*?(\w+)\s+Preference:.*",
                               network_interface="Interface: (.*)")

    vrf_rule = dict(name="(.*): \d* destinations")

    network_name_rule = dict(name="(.*) \(.* ent")

    def parse(self, data):
        try:
            result = []
            parser = LineBasedBlockParser("(.*) \(.* ent")
            blocks = parser.parse(data)
            generic_parser = GenericTextParser()
            vrf_name = generic_parser.parse(blocks[0], self.vrf_rule)[0]
            if "inet6.0" in vrf_name['name']:
                return result
            vrf = "master" if vrf_name['name'] == "inet.0" else vrf_name['name'].split('.inet.0')[0]

            for block in blocks[1:]:
                parser = LineBasedBlockParser("\*?(\w+)\s+Preference:.*")
                line_blocks = parser.parse(block)
                network_name = generic_parser.parse(line_blocks[0], self.network_name_rule)[0]

                for idx, line_block in enumerate(line_blocks[1:]):
                    routes = generic_parser.parse(line_block, self.route_rules)[0]
                    if routes['next_hop_type'] == "Receive": continue
                    routes.pop('next_hop_type')
                    if not routes['interfaceName'] and not routes['network_interface']: continue
                    routes.update({"vrf": vrf})
                    routes.update({"network": "{}".format(network_name['name'])})
                    routes.update({"name": "{}_{}".format(network_name['name'], idx)})
                    routes.update({"interfaceName": routes['interfaceName'] if routes['interfaceName']
                                                                            else routes['network_interface']})
                    routes.pop('network_interface')
                    routes.update({"routeType": "{}".format(routes['routeType'] if routes['nextHop'] else "DIRECT")})
                    routes.update({"nextHop": "{}".format(routes['nextHop'] if routes['nextHop'] else "DIRECT")})
                    result.append(routes.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class JuniperMACTableTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        result = []
        for mac in tables['showMacTable']:
            for port in tables['showInterface']:
                if mac['switchPort'] == port['name']:
                    mac['vlan'] = port['vlans']
                    mac.pop('address')
                    mac.pop('Flags')
                    result.append(mac)
        return result


class JuniperVRFParser(PrePostProcessor):

    def parse(self, data):
        result = []
        temp = {}
        vrf_data = data.splitlines()
        router_id = vrf_data[1].split(":")[1].lstrip()
        if "0.0.0.0" == router_id:
            return result
        vrf_name = vrf_data[0].split(':')[0]
        temp['name'] = "{}".format(vrf_name)
        temp['interfaces'] = ",".join(self.get_interface(data))
        result.append(temp)
        return result

    @staticmethod
    def get_interface(vrf):
        interfaces = []
        got_interface = False
        if "Interfaces:" in vrf:
            for i in vrf.splitlines():
                if "Interfaces:" == i:
                    got_interface = True
                    interfaces = []
                    continue
                if ":" in i and got_interface:
                    break
                interfaces.append(i)
        return interfaces


class JuniperNeighborsTableParser(PrePostProcessor):

    def parse(self, data):
        result = []

        for line in data.splitlines():
            if not line or "Local Interface" in line: continue
            line_tokenizer = LineTokenizer()
            line_token = line_tokenizer.tokenize(line)
            temp = {}
            temp.update({"localInterface": "{}".format(line_token[0])})
            temp.update({"remoteInterface": "{}".format(line_token[5])})
            temp.update({"remoteDevice": "{}".format(line_token[-1])})
            result.append(temp)
        return result
