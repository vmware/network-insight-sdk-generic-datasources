import re
import traceback
import ipaddress

from common.log import py_logger
from netaddr import IPAddress
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor
from parsers.common.block_parser import LineBasedBlockParser
from parsers.common.text_parser import GenericTextParser
from parsers.text.table_processor import TableProcessor


class AOSSwitchInfoPrePostProcessor(PrePostProcessor):
    """
        Get details of Alcatel-Lucent switch.
    """

    def parse(self, data):
        """
        Get details of Alcatel-Lucent switch
        :param data: Parsed output of show system command
        :return: list with dictionary containing Alcatel-Lucent switch details
        """
        info = {}
        model_pattern = "Alcatel[-]?Lucent\\s+Enterprise?\\s+(\\S+).*"
        version_pattern = "Alcatel[-]?Lucent\\s+Enterprise?\\s+[\\S]*([^,]+),"
        name_pattern = "Name:\\s+(\\S+),"
        model_match = re.search(model_pattern, data)
        if model_match:
            info['model'] = model_match.group(1).strip()
        version_match = re.search(version_pattern, data)
        if version_match:
            info['version'] = version_match.group(1).strip()
        name_match = re.search(name_pattern, data)
        if name_match:
            info['hostname'] = name_match.group(1).strip()

        info['vendor'] = "Alcatel-Lucent"
        info['haState'] = "ACTIVE"
        info['name'] = info['hostname']
        return [info]


def find_vlans_for_port(port_vlan_info, port_id):
    for port_dict in port_vlan_info:
        if port_dict['portId'] == port_id:
            vlan_ids = [vlan_info['vlanId'] for vlan_info in port_dict['values']]
            return ','.join(vlan_ids)
    return ''


def find_port_mode(port_vlan_info, port_id):
    for port_dict in port_vlan_info:
        if port_dict['portId'] == port_id:
            for vlan_info in port_dict['values']:
                if 'tagged' in vlan_info['type']:
                    return 'TRUNK'
            return 'ACCESS'
    return 'OTHER'


class AOSSwitchPortPrePostProcessor(PrePostProcessor):
    """
        Get switch ports using show interfaces command
    """

    def post_process(self, data):
        """
        Parse show interfaces command output to get switch ports
        :param data: show interfaces command output
        :return: List of dictionaries of switch ports
        """
        result = []
        for d in data:
            if d['name'] is None or d['name'].strip() is '':
                continue

            if 'interfaceSpeed' in d and d['interfaceSpeed'].strip().isdigit():
                d['interfaceSpeed'] = str(int(d['interfaceSpeed'].strip()) * 1000000)
                d['operationalSpeed'] = d['interfaceSpeed']
            if 'duplex' in d:
                if d['duplex'] == 'Half':
                    d['duplex'] = 'HALF'
                elif d['duplex'] == 'Full':
                    d['duplex'] = 'FULL'
                elif d['duplex'] == 'Auto':
                    d['duplex'] = 'AUTO'
                else:
                    d['duplex'] = 'OTHER'
            if 'operationalStatus' in d:
                if d['operationalStatus'] == 'up':
                    d['administrativeStatus'] = 'UP'
                    d['operationalStatus'] = 'UP'
                    d['connected'] = 'true'
                else:
                    d['administrativeStatus'] = 'DOWN'
                    d['operationalStatus'] = 'DOWN'
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


class AOSSwitchPortTableProcessor(TableProcessor):

    def process_tables(self, tables):
        interfaces_t = tables['switchPorts']
        vlans_t = tables['vlanMembers']
        result = []
        for port in interfaces_t:
            port['vlans'] = find_vlans_for_port(vlans_t, port['name'])
            port['switchPortMode'] = find_port_mode(vlans_t, port['name'])
            result.append(port)

        return result


class AOSPortChannelsTableProcessor(PrePostProcessor):

    def process_tables(self, tables):
        pc_members_t = tables['showPCMembers']
        vlans_t = tables['vlanMembers']
        pc_t = tables['showPC']

        port_channel_map = {}
        for entry in pc_members_t:
            port_channel_num = entry['port_channel']
            member_port = entry['member_port']
            is_active = entry['primary_port'] == 'YES'

            if port_channel_num not in port_channel_map:
                port_channel_map[port_channel_num] = {'active': [], 'passive': []}

            if is_active:
                port_channel_map[port_channel_num]['active'].append(member_port)
            else:
                port_channel_map[port_channel_num]['passive'].append(member_port)

        output_lines = []
        for r in pc_t:
            d = {}
            d.update(name='Po'+r['port_channel'])
            if r['admin_state'] == 'ENABLED':
                d.update(administrativeStatus='UP')
            else:
                d.update(administrativeStatus='DOWN')

            if r['oper_state'] == 'UP':
                d.update(operationalStatus='UP')
                d.update(connected=True)
            else:
                d.update(operationalStatus='DOWN')
                d.update(connected=False)

            if r['port_channel'] in port_channel_map:
                active_members = port_channel_map[r['port_channel']]['active']
                passive_members = port_channel_map[r['port_channel']]['passive']
                d.update(activePorts=','.join(active_members))
                d.update(passivePorts=','.join(passive_members))

            d.update(vlans=find_vlans_for_port(vlans_t, d['name']))
            d.update(switchPortMode=find_port_mode(vlans_t, d['name']))
            output_lines.append(d)

        return output_lines


class AOSVlanMembersPrePostProcessor(PrePostProcessor):
    """
        Parse vlan members of Alcatel-Lucent switch.
    """

    def parse(self, data):
        port_vlan_info = []
        lines = data.strip().split('\n')
        end_of_header = False
        current_vlan_id = None

        for line in lines:
            if "--" in line:
                end_of_header = True
            if not end_of_header:
                continue

            words = line.split()

            if len(words) == 4:
                # Regular line with all fields
                vlan_id, member_port, vlan_type, _ = words
                port_vlan_info = self.update_port_info(port_vlan_info, replace_zero_prefix_with_po(member_port), vlan_id,
                                                       vlan_type)
                current_vlan_id = vlan_id
            elif len(words) == 3:
                # Spilled-over line without vlanId
                if current_vlan_id is not None:
                    port_vlan_info = self.update_port_info(port_vlan_info, replace_zero_prefix_with_po(words[0]), current_vlan_id,
                                                           words[1])

        return port_vlan_info

    @staticmethod
    def update_port_info(port_info, member_port, vlan_id, vlan_type):
        for port_dict in port_info:
            if port_dict['portId'] == member_port:
                port_dict['values'].append({
                    'vlanId': vlan_id,
                    'type': vlan_type
                })
                return port_info

        port_info.append({
            'portId': member_port,
            'values': [{
                'vlanId': vlan_id,
                'type': vlan_type
            }]
        })
        return port_info


class AOSNeighborsParser(PrePostProcessor):
    rules = dict(localInterface="Remote LLDP nearest-bridge Agents on Local Port\\s+(.*):",
                 remoteInterface=".*Port Description\\s+=\\s+(.*),",
                 remoteDevice=".*System Name\\s+=\\s+(.*),")

    def parse(self, data):
        """
            Parse show lldp remote-system command output
        """
        try:
            result = []
            parser = LineBasedBlockParser("Remote LLDP nearest-bridge Agents")
            blocks = parser.parse(data)
            generic_parser = GenericTextParser()

            for block in blocks[1:]:
                neighbor_info = generic_parser.parse(block, self.rules)[0]
                local_port = neighbor_info['localInterface']
                remote_port = neighbor_info['remoteInterface']
                remote_system = neighbor_info['remoteDevice']

                if local_port is None or remote_port is None or remote_system is None or 'null' in remote_system \
                        or 'null' in remote_port:
                    py_logger.info("local port {}, remote port {}, remote device {}\n".format(local_port, remote_port,
                                                                                              remote_system))
                    continue

                result.append(neighbor_info.copy())
        except Exception as e:
            py_logger.error("{}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


def replace_zero_prefix_with_po(text):
    if text.startswith("0/"):
        return 'Po'+text[2:] # port channels use 0/ prefix in alcatel switches.
    else:
        return text


class AOSMacAddressTableParser(PrePostProcessor):

    def parse(self, data):

        result = []
        try:
            lines = data.strip().split('\n')
            end_of_header = False

            for line in lines:
                if "--" in line:
                    end_of_header = True
                if not end_of_header:
                    continue

                words = line.split()
                d = {}
                if len(words) == 6 and words[0] == 'VLAN':
                    d.update(macAddress=words[2])
                    d.update(vlan=words[1])
                    d.update(switchPort=replace_zero_prefix_with_po(words[-1]))
                    result.append(d)

        except Exception as e:
            py_logger.error("MAC Address table - {}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class AOSIpInterfaceParser(PrePostProcessor):

    def parse(self, data):

        result = []
        try:
            lines = data.strip().split('\n')
            end_of_header = False

            for line in lines:
                if "--" in line:
                    end_of_header = True
                if not end_of_header:
                    continue

                words = line.split()
                d = {}
                if len(words) == 7:
                    d.update(ipAddress=words[1]+'/'+str(IPAddress(words[2]).netmask_bits()))
                    d.update(name=words[0])
                    d.update(vrf='default')

                    if words[3] == 'UP':
                        d.update(operationalStatus='UP')
                        d.update(administrativeStatus='UP')
                        d.update(connected=True)
                    else:
                        d.update(operationalStatus='DOWN')
                        d.update(administrativeStatus='DOWN')
                        d.update(connected=False)

                    if words[-1].isnumeric():
                        d.update(vlan=words[-1])

                    result.append(d)

        except Exception as e:
            py_logger.error("IP Interfaces - {}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class AOSIpRouteParser(PrePostProcessor):

    def parse(self, data):

        result = []
        try:
            lines = data.strip().split('\n')
            end_of_header = False

            for line in lines:
                if "--" in line:
                    end_of_header = True
                if not end_of_header:
                    continue

                words = line.split()
                d = {}
                if len(words) == 4:
                    d.update(name=words[0])
                    d.update(network=words[0])
                    d.update(vrf='default')
                    d.update(nextHop=words[1])
                    d.update(interfaceName='')
                    d.update(routeType=words[-1].lower())

                    result.append(d)

        except Exception as e:
            py_logger.error("Routes - {}\n{}".format(e, traceback.format_exc()))
            raise e
        return result


class AOSRoutesTableProcessor(TableProcessor):

    def process_tables(self, data):
        routes_t = data['showIPRoute']
        router_interfaces_t = data['router-interfaces']
        result = []
        for r in routes_t:
            new_route = r.copy()
            interfaceName = find_interface_name(r['nextHop'], router_interfaces_t)
            if interfaceName:
                new_route.update(interfaceName=interfaceName)
                result.append(new_route)

        return result


def find_interface_name(ip_to_find, interfaces):
    ip_to_find = ipaddress.IPv4Address(ip_to_find)
    for interface in interfaces:
        ip_range = ipaddress.IPv4Network(interface['ipAddress'], strict=False)
        if ip_to_find in ip_range:
            return interface['name']
    return None
