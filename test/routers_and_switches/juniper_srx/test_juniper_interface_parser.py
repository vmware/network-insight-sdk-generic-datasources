import unittest
from network_insight_sdk_generic_datasources.routers_and_switches.juniper_srx.juniper_srx_pre_post_processor import \
    JuniperInterfaceParser
from network_insight_sdk_generic_datasources.parsers.common.block_parser import LineBasedBlockParser


class JuniperInterfaceParserTestCase(unittest.TestCase):
    def test_post_process(self):
        text = """Physical interface: reth0  , Enabled, Physical link is Up
        \n  Interface index: 128, SNMP ifIndex: 564, Generation: 131
        \n  Link-level type: Ethernet, MTU: 1518, Speed: 2Gbps, BPDU Error: None, \
        MAC-REWRITE Error: None, Loopback: Disabled, Source filtering: Disabled, \
        Flow control: Disabled, Minimum links needed: 1,
        \n  Minimum bandwidth needed: 1bps
        \n  Device flags   : Present Running
        \n  Interface flags: SNMP-Traps Internal: 0x0
        \n  Current address: 00:10:db:ff:8c:00, Hardware address: 00:10:db:ff:8c:00
        \n  Last flapped   : 2019-02-24 20:51:57 CET (16w3d 16:35 ago)
        \n  Statistics last cleared: Never
        \n  Traffic statistics:
        \n   Input  bytes  :       18434583177834             22883312 bps
        \n   Output bytes  :       18411424061721             23831792 bps
        \n   Input  packets:          76522926891                13834 pps
        \n   Output packets:          75943393603                14199 pps
        \n  Ingress queues: 8 supported, 4 in use
        \n  Queue counters:       Queued packets  Transmitted packets      Dropped packets
        \n    0                                0                    0                    0
        \n    1                                0                    0                    0
        \n    2                                0                    0                    0
        \n    3                                0                    0                    0
        \n  Egress queues: 8 supported, 4 in use
        \n  Queue counters:       Queued packets  Transmitted packets      Dropped packets
        \n    0                       2799436507           2799436161                  346
        \n    1                                0                    0                    0
        \n    2                                0                    0                    0
        \n    3                        168851794            168851794                    0
        \n  Queue number:         Mapped forwarding classes
        \n    0                   best-effort
        \n    1                   expedited-forwarding
        \n    2                   assured-forwarding
        \n    3                   network-control
        \n\n  Logical interface reth0.26 (Index 149) (SNMP ifIndex 704) (Generation 216)
        \n    Description: NL-IX NAWAS\n    Flags: Up SNMP-Traps 0x0 VLAN-Tag [ 0x8100.26 ]  Encapsulation: ENET2
        \n    Statistics        Packets        pps         Bytes          bps
        \n    Bundle:
        \n        Input :       3013850          0     206415986          464
        \n        Output:        561728          0      55373670            0
        \n    Adaptive Statistics:
        \n        Adaptive Adjusts:          0
        \n        Adaptive Scans  :          0
        \n        Adaptive Updates:          0
        \n    Link:\
        \n      ge-0/0/4.26\
        \n        Input :       1053214          0      70376818          232\
        \n        Output:        561728          0      55373670            0\
        \n      ge-0/0/5.26\n        Input :        546267          0      39181638            0\
        \n        Output:             0          0             0            0\
        \n      ge-9/0/4.26\n        Input :        940863          0      62765122          232\
        \n        Output:             0          0             0            0\
        \n      ge-9/0/5.26\
        \n        Input :        473506          0      34092408            0\
        \n        Output:             0          0             0            0\
        \n    Marker Statistics:   Marker Rx     Resp Tx   Unknown Rx   Illegal Rx\
        \n      ge-0/0/4.26                0           0            0            0\
        \n      ge-0/0/5.26                0           0            0            0\
        \n      ge-9/0/4.26                0           0            0            0\
        \n      ge-9/0/5.26                0           0            0            0\
        \n    Security: Zone: untrust\n    Allowed host-inbound traffic : https ike ping snmp ssh traceroute\
        \n    Flow Statistics :\
        \n    Flow Input statistics :\n      Self packets :                     1156483\n      \
        ICMP packets :                     4\n      VPN packets :                      0\
        \n      Multicast packets :                1996824\n      Bytes permitted by policy :        9199328\
        \n      Connections established :          0\n    Flow Output statistics:\
        \n      Multicast packets :                0\n      Bytes permitted by policy :        13799621\
        \n    Flow error statistics (Packets dropped due to):\n      Address spoofing:                  0
        \n      Authentication failed:             0\n      Incoming NAT errors:               0
        \n      Invalid zone received packet:      0\n      Multiple user authentications:     0
        \n      Multiple incoming NAT:             0\n      No parent for a gate:              0
        \n      No one interested in self packets: 0\n      No minor session:                  0
        \n      No more sessions:                  0\n      No NAT gate:                       0
        \n      No route present:                  0\n      No SA for incoming SPI:            0
        \n      No tunnel found:                   0\n      No session for a gate:             0
        \n      No zone or NULL zone binding       0\n      Policy denied:                     0
        \n      Security association not active:   0\n      TCP sequence number out of window: 0
        \n      Syn-attack protection:             0\n      User authentication errors:        0
        \n    Protocol inet, MTU: 1500, Generation: 237, Route table: 0
        \n      Flags: Sendbcast-pkt-to-re
        \n      Addresses, Flags: Is-Preferred Is-Primary
        \n        Destination: 213.207.10.0/26, Local: 213.207.10.56, Broadcast: 213.207.10.63, Generation: 183
        \n    Protocol inet6, MTU: 1500
        \n    Max nh cache: 100000, New hold nh limit: 100000, Curr nh cnt: 1, Curr new hold cnt: 0, NH drop cnt: 0
        \n    Generation: 238, Route table: 0
        \n      Flags: None
        \n      Addresses, Flags: Is-Preferred Is-Primary
        \n        Destination: 2a02:10:3::/64, Local: 2a02:10:3::a505:1299:1
        \n    Generation: 185
        \n      Addresses, Flags: Is-Preferred
        \n        Destination: fe80::/64, Local: fe80::210:db00:1aff:8c00
        \n    Generation: 187"""

        expected_output = [{'name': 'reth0  ', 'administrativeStatus': 'UP', 'mtu': '1518', 'operationalStatus': 'UP',
                            'connected': 'TRUE', 'members': '', 'hardwareAddress': '00:10:db:ff:8c:00',
                            'ipAddress': ''},
                           {'name': 'reth0.26', 'administrativeStatus': 'UP', 'mtu': '1518', 'operationalStatus': 'UP',
                            'connected': 'TRUE', 'members': 'ge-0/0/4.26,ge-0/0/5.26,ge-9/0/4.26,ge-9/0/5.26',
                            'hardwareAddress': '00:10:db:ff:8c:00', 'ipAddress': '213.207.10.56/26'}]

        parser = LineBasedBlockParser(line_pattern="Physical interface:")

        data = parser.parse(text)
        parser = JuniperInterfaceParser()
        result = parser.parse(data[0])
        self.assertEqual(len(result), 2)
        self.assertEqual(type(result), list)
        self.assertEqual(expected_output, result)


if __name__ == '__main__':
    unittest.main()
