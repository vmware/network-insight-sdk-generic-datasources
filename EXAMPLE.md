Cisco N5K Device Integration Process
=======================================

This document shows process or method on how to approach problems faced during writing YAML configuration or
Pre-Post Processors for a device.

Here, we have taken Cisco N5K as example to demonstrate thought process.

Entire parsing pipeline/steps/framework is/are as follows

1. Execute Commands - Commands are defined in command list.
2. Pre Process Command Output (if required)
3. Parse Output (Tabular Data) 
4. Post Process (if required) (Tabular Data)
5. Join Tables (referred to by table_id/joined_table_id)
6. Write tables to CSV
7. Zip the csv files.

All of the above steps are driven by YAML configuration file. Hence, we first need to define YAML configuration. Sample 
structure has already been provided. User only needs to focus on YAML configuration and, if required, then writing
Pre-Post Processors. Rest of the steps are taken care by framework.

To support any device we need to first know what network information we need to capture. These pieces of information
are Router Interfaces, Routes, VRFs, Switch Ports, etc. Each information piece is depicted in the form of CSV file. 
Therefore, we would first find out commands to execute in Cisco N5K Device which we can use to fetch these information. 

Let's cover integration process by considering few examples

1. [ Routes ](#routes)
2. [ Switch Ports ](#switch-ports)

<a name="routes"></a>
## 1. Routes
We need to fill up details required by routes.csv file. Upon investigation we would find that following command give all
 necessary fields required by routes.csv file.

Idea is to cover all the fields in single command, if possible. This makes it easy to process down the pipeline. Below
command gives routes for all the VRFs and suffices all the fields required by routes.csv file.
`show ip route vrf all`

```
# show ip route vrf all
IP Route Table for VRF "management"
'*' denotes best ucast next-hop
'**' denotes best mcast next-hop
'[x/y]' denotes [preference/metric]

0.0.0.0/0, ubest/mbest: 1/0
    *via 10.10.13.253, mgmt0, [1/0], 36w1d, static
3.3.0.0/24, ubest/mbest: 1/0
    *via 10.10.13.253, mgmt0, [1/0], 36w1d, static

IP Route Table for VRF "KEEPALIVE"
'*' denotes best ucast next-hop
'**' denotes best mcast next-hop
'[x/y]' denotes [preference/metric]

172.16.241.0/24, ubest/mbest: 1/0, attached
    *via 172.16.241.11, Vlan200, [0/0], 36w1d, direct
172.16.241.11/32, ubest/mbest: 1/0, attached
    *via 172.16.241.11, Vlan200, [0/0], 36w1d, local
```

Looking at the output we quickly observe that a block with VRF having route table. Each block starts with line
`IP Route Table for VRF`. Therefore, we use `GenericBlockParser` with line_pattern `IP Route Table for VRF` to first 
take out the blocks and then perform pre-process using `CiscoRoutePrePostProcessor` where we convert double line route 
output to single line and create output data in tabular format with data in rows and column headers representing data.

Since, `HorizontalTableParser` suites well for tabular data we used same for parsing and created dictionary 
(key-value pair). Here, we only choose data which are relevant for routes.csv file and ignore rest.

NOTE: All the parsers produce output as list of dictionaries.

<a name="switch-ports"></a>
## 2. Switch Ports
Now let's look filling up details required by switch ports csv file. Here, we need to execute two commands because not 
all the columns can be filled up using single command. 

```
# show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Eth1/3, Eth1/4, Eth1/5, Eth1/6
                                                Eth1/7, Eth1/8, Eth1/9, Eth1/10
                                                Eth1/11, Eth1/12, Eth1/13
                                                Eth1/14, Eth1/15, Eth1/16
                                                Eth1/17, Eth1/18, Eth1/19
                                                Eth1/20, Eth1/28, Eth1/29
                                                Eth1/30, Eth100/1/1, Eth100/1/3
                                                Eth100/1/7, Eth100/1/9
                                                Eth100/1/11, Eth100/1/13
                                                Eth100/1/14, Eth100/1/17
                                                Eth100/1/19, Eth100/1/21
                                                Eth100/1/22, Eth100/1/23
                                                Eth100/1/24, Eth100/1/25
                                                Eth100/1/26, Eth100/1/27
                                                Eth100/1/29, Eth100/1/30
                                                Eth100/1/31, Eth100/1/32
13   VLAN0013                         active    Eth1/2, Eth1/11, Eth1/21
                                                Eth1/22, Eth1/23, Eth1/24
                                                Eth1/25, Eth1/26, Eth1/27
                                                Eth100/1/1, Eth100/1/9
                                                Eth100/1/13, Eth100/1/19
                                                Eth100/1/21, Eth100/1/22
                                                Eth100/1/25, Eth100/1/26
                                                Eth100/1/28, Eth100/1/29
``` 
Since above output a tabular with some deviations like column data spilling over next row, we will
format so that data is tabular without spill over. We used `CiscoInterfaceVlanPrePostProcessor.pre_process()` to do this 
job. Furthermore, we wanted to create dat in such a way that ports to vlans map can be queries. This is done in
`CiscoInterfaceVlanPrePostProcessor.post_process()`


To get other attributes of switch ports. We hit following command.
```
# show interface 
Ethernet1/1 is down (Link not connected)
  Hardware: 1000/10000 Ethernet, address: 002a.6a70.ae01 (bia 002a.6a70.adc8)
  MTU 1500 bytes, BW 10000000 Kbit, DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA
  auto-duplex, 10 Gb/s, media type is 10G
  Beacon is turned off
  Input flow-control is off, output flow-control is off
  Rate mode is dedicated
  Switchport monitor is off 
  EtherType is 0x8100 
  Last link flapped never
  Last clearing of "show interface" counters never
  30 seconds input rate 0 bits/sec, 0 packets/sec
  30 seconds output rate 0 bits/sec, 0 packets/sec
  Load-Interval #2: 5 minute (300 seconds)
    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps
  RX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 input packets  0 bytes
    0 jumbo packets  0 storm suppression bytes
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
  TX
    0 unicast packets  0 multicast packets  0 broadcast packets
    0 output packets  0 bytes
    0 jumbo packets
    0 output errors  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble 0 output discard
    0 Tx pause
  0 interface resets

Ethernet1/2 is up
  Hardware: 1000/10000 Ethernet, address: 002a.6a70.adc9 (bia 002a.6a70.adc9)
  Description: 4500 Active Port 11
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec
  reliability 255/255, txload 2/255, rxload 1/255
  Encapsulation ARPA
  Port mode is trunk
  full-duplex, 1000 Mb/s, media type is 10G
  Beacon is turned off
  Input flow-control is off, output flow-control is off
  Rate mode is dedicated
  Switchport monitor is off 
  EtherType is 0x8100 
  Last link flapped 36week(s) 2day(s)
  Last clearing of "show interface" counters 36w2d
  30 seconds input rate 1108256 bits/sec, 414 packets/sec
  30 seconds output rate 5933232 bits/sec, 686 packets/sec
  Load-Interval #2: 5 minute (300 seconds)
    input rate 789.52 Kbps, 351 pps; output rate 10.31 Mbps, 967 pps
  RX
    4906019096 unicast packets  347776934 multicast packets  40781622 broadcast packets
    5294577652 input packets  1608586074753 bytes
    310633283 jumbo packets  0 storm suppression bytes
    0 runts  0 giants  0 CRC  0 no buffer
    0 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop
    0 input with dribble  0 input discard
    0 Rx pause
  TX
    12053440606 unicast packets  124476161 multicast packets  4232432 broadcast packets
    12182149199 output packets  14301655330997 bytes
    8321835888 jumbo packets
    0 output errors  0 collision  0 deferred  0 late collision
    0 lost carrier  0 no carrier  0 babble 0 output discard
    0 Tx pause
  1 interface resets

```

Output is format repeating block with line pattern `(\w+) is (up|down)`. For each block
we use `GenericTextParser` where we specify regex pattern in key(columnName) and value(regex with group selection 
using parenthesis). For <b>name</b> field we used configuration as below defined under <b>rules</b>.
`name: "(.*) is (?:up|down).*"` Question mark is used to forget the second match. Therefore, regex will remember only 
first match surrounded using parenthesis.

Once above two commands are parsed and result is list of dictionaries (tabular representation), now outputs can be 
merged with table joiners. Tables created by executing above commands are referred using `table_id`. Now to join tables,
parameters required by `SimpleTableJoiner` are `source_table`, `source_column`, `destination_table` and `destination_column`.
Resulting table is referred by `joined_table_id`. 
