# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from netaddr import IPAddress
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor


class DellSwitchPrePostProcessor(PrePostProcessor):
    """
    Get details of dell switch
    """
    def post_process(self, data):
        """
        Get details of dell
        :param data: Parsed output of show version command
        :return: list with dict containing DELL switch details
        """
        temp = data[0]
        temp['vendor'] = "DELL"
        temp['haState'] = "ACTIVE"
        return [temp]



class DellPortChannelPrePostParser(PrePostProcessor):
    def parse(self, data):
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
                    administrativeStatus="up",
                    operationalStatus="up",
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

    def post_process(self, data):
        result = []
        for d in data:
            result.append(dict(localInterface=d['interface'],
                               remoteDevice=d['System Name'],
                               remoteInterface=['Port ID']))
        return result


class DellIPInterfacesPrePostParser(PrePostProcessor):

    def post_process(self, data):
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
            if 'switchPortMode' in d:
                if d['switchPortMode'] == 'access':
                    d['switchPortMode'] = 'ACCESS'
                elif d['switchPortMode'] == 'trunk':
                    d['switchPortMode'] = 'TRUNK'
                else:
                    d['switchPortMode'] = 'OTHER'
        return result
