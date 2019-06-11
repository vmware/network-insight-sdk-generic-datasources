Cisco N5K Device Integration Process
=======================================

This document shows process or method on how to approach problems faced during writing YAML configuration or
Pre-Post Processors for a device.

To support any device we need to first know what network information we need to capture. These informations
are Router Interfaces, Routes, VRFs, Switch Ports, etc. Therefore we would first find out commands in Cisco Device 
which we can use to fetch these information. 

Let's take a small example on fetching routes and filling up details required by routes.csv file.
Upon investigation we would find that following command give all necessary information/fields required by routes.csv file.

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
output to single line and create output data in tabular format. 

<br/>

Since `HorizontalTableParser` suites well for tabular data we used same for parsing data and create dictionary 
(key-value pair). Here, we only choose data which are relevant for routes.csv file and ignore rest.
 

