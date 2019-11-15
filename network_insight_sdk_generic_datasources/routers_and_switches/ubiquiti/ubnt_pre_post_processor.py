# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause


import re

from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor


class UBNTVersionPrePostProcessor(PrePostProcessor):

    def pre_process(self, data):
        return data

    def post_process(self, data):
        result = []
        new_d = {}
        for d in data:
            if 'Version' in d:
                new_d['os'] = d['Version']
            if 'HW model' in d:
                new_d['model'] = d['HW model']
            if 'HW S/N' in d:
                new_d['serial'] = d['HW S/N']

        new_d['haState'] = "ACTIVE"
        new_d['vendor'] = "Ubiquiti Networks"
        new_d['name'] = "CHANGEME"
        new_d['hostname'] = "CHANGEME"

        # rearrange for the right order (4.1 requires it)
        new_new_d = dict()
        new_new_d['name'] = new_d['name']
        new_new_d['serial'] = new_d['serial']
        new_new_d['os'] = new_d['os']
        new_new_d['model'] = new_d['model']
        new_new_d['vendor'] = new_d['vendor']
        new_new_d['hostname'] = new_d['hostname']
        new_new_d['haState'] = new_d['haState']

        result.append(new_new_d)

        return result


class UBNTMacPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        result = []
        for d in data:
            vlan = 1
            # if there's a dot in the interface name, it's a VLAN. In that case, extract the VLAN ID
            if '.' in d['Iface']:
                match = re.match("eth\d+\.(\d+)", d['Iface'])
                vlan = match.group(1)

            # put the VLAN ID in the results table
            d.update({'vlan': vlan})
            result.append(d)
        return result


class UBNTLLDPPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        result = []
        for d in data:
            # strip whitespaces of values and remove the prefix "ifname" from the remote interface
            d['localInterface']  = d['localInterface'].strip()
            d['remoteInterface'] = d['remoteInterface'].strip().replace("ifname ", "")
            d['remoteDevice']    = d['remoteDevice'].strip()
            result.append(d)
        return result

class UBNTRoutePrePostProcessor(PrePostProcessor):

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
            #if 'via' in line:
            #    output_lines[-1] = output_lines[-1] + ' ' + line
            #    continue
            output_lines.append(line)

        if len(output_lines) == 0:
            return ''

        for i in range(0, len(output_lines)):
            line = output_lines[i]
            import re

            if re.match(r'^C', line):
                regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}) is directly connected, (.*)"

                matches = re.finditer(regex, line, re.MULTILINE)
                for matchNum, match in enumerate(matches, start=1):
                    groups = match.groups()
                    name = groups[0]
                    network = groups[0]
                    nextHop = groups[1]
                    interfaceName = groups[1]
                    routeType = 'direct'

            elif re.match(r'^S', line):
                regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}).*via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), (.*)"
                matches = re.finditer(regex, line, re.MULTILINE)
                for matchNum, match in enumerate(matches, start=1):
                    #print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
                    groups = match.groups()
                    name = groups[0]
                    network = groups[0]
                    nextHop = groups[1]
                    interfaceName = groups[2]
                    routeType = 'static'

            # O E2 *> 10.8.200.0/24 [110/0] via 10.8.91.254, eth1.300, 02w6d09h
            else:
                regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}).*via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), (.*),"
                matches = re.finditer(regex, line, re.MULTILINE)
                for matchNum, match in enumerate(matches, start=1):
                    #print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
                    groups = match.groups()
                    name = groups[0]
                    network = groups[0]
                    nextHop = groups[1]
                    interfaceName = groups[2]

                    # for future, when/if UANI can tell the difference between bgp/ospf/dynamic routes
                    if re.match(r'^B', line):
                        routeType = 'dynamic'
                    elif re.match(r'^O', line):
                        routeType = 'dynamic'
                    else:
                        routeType = 'dynamic'

            output_lines[i] = "{}\t{}\t{}\t{}\t{}\t{}".format(name, network, nextHop, interfaceName, routeType, vrf)

        return '\n'.join(output_lines)


class UBNTSwitchPortPrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        result = []

        for d in data:

            # fill out some details that are missing from the UBNT output
            if 'interfaceSpeed' not in d:
                d['interfaceSpeed'] = '1000000'
            if 'operationalSpeed' not in d:
                d['operationalSpeed'] = '1000000'
            if 'duplex' not in d:
                d['duplex'] = 'FULL'

            if 'connected' in d:
                if d['connected'] == 'UP':
                    d['connected'] = 'TRUE'
                else:
                    d['connected'] = 'FALSE'

            if '@' in d['name']:
                d['name'] = d['name'].split('@', 1)[0]

            if '.' in d['name']:
                d['switchPortMode'] = 'ACCESS'
            else:
                d['switchPortMode'] = 'TRUNK'

            if '.' in d['name']:
                d['vlans'] = d['name'].split('.', 1)[1]
            else:
                d['vlans'] = 1

            result = [d]
        return result

class UBNTRouterInterfacePrePostProcessor(PrePostProcessor):

    def post_process(self, data):
        #print("Starting post_process")
        result = []

        for d in data:

            # fill out some details that are missing from the UBNT output
            if 'interfaceSpeed' not in d:
                d['interfaceSpeed'] = '1000000'
            if 'operationalSpeed' not in d:
                d['operationalSpeed'] = '1000000'
            if 'vrf' not in d:
                d['vrf'] = 'default'
            if 'ipAddress' not in d:
                d['ipAddress'] = ''
            #if 'duplex' not in d:
            #    d['duplex'] = 'FULL'

            if 'connected' in d:
                if d['connected'] == 'UP':
                    d['connected'] = 'TRUE'
                else:
                    d['connected'] = 'FALSE'

            if '@' in d['name']:
                d['name'] = d['name'].split('@', 1)[0]

            if '.' in d['name']:
                d['vlan'] = d['name'].split('.', 1)[1]
            else:
                d['vlan'] = 1

            result = [d]
        return result


class UBNTVrfPrePostProcessor(PrePostProcessor):
    # UBTN doesn't have VRFs, so just return an array with the value "default" as the main VRF name
    def pre_process(self, data):
        result = "name\ndefault"
        return result


class UBNTRouterInterfaceVrfPrePostProcessor(PrePostProcessor):
    # UBTN doesn't have VRFs, so just return an array with the value "default" as the main VRF name
    def post_process(self, data):
        result = []
        for d in data:
            d['interfaceName'] = d['interfaceName'].split('@', 1)[0]
            d['vrf'] = "default"
            result = [d]
        return result
