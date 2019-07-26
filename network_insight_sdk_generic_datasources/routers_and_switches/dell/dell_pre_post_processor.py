# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import re
from network_insight_sdk_generic_datasources.parsers.text.pre_post_processor import PrePostProcessor


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
