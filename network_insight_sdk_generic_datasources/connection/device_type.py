# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

from enum import Enum, unique


@unique
class DeviceType(Enum):
    A10 = 1
    ACCEDIAN = 2
    ALCATEL_AOS = 3
    ALCATEL_SROS = 4
    APRESIA_AEOS = 5
    ARISTA_EOS = 6
    ARUBA_OS = 7
    AVAYA_ERS = 8
    AVAYA_VSP = 9
    BROCADE_FASTIRON = 10
    BROCADE_NETIRON = 11
    BROCADE_NOS = 12
    BROCADE_VDX = 13
    BROCADE_VYOS = 14
    CHECKPOINT_GAIA = 15
    CALIX_B6 = 16
    CIENA_SAOS = 17
    CISCO_ASA = 18
    CISCO_IOS = 19
    CISCO_NXOS = 20
    CISCO_S300 = 21
    CISCO_TP = 22
    CISCO_WLC = 23
    CISCO_XE = 24
    CISCO_XR = 25
    CORIANT = 26
    DELL_DNOS9 = 27
    DELL_FORCE10 = 28
    DELL_OS6 = 29
    DELL_OS9 = 30
    DELL_OS10 = 31
    DELL_POWERCONNECT = 32
    DELL_ISILON = 33
    ELTEX = 34
    ENTERASYS = 35
    EXTREME = 36
    EXTREME_ERS = 37
    EXTREME_EXOS = 38
    EXTREME_NETIRON = 39
    EXTREME_NOS = 40
    EXTREME_SLX = 41
    EXTREME_VDX = 42
    EXTREME_VSP = 43
    EXTREME_WING = 44
    F5_LTM = 45
    F5_TMSH = 46
    F5_LINUX = 47
    FORTINET = 48
    GENERIC_TERMSERVER = 49
    HP_COMWARE = 50
    HP_PROCURVE = 51
    HUAWEI = 52
    HUAWEI_VRPV8 = 53
    IPINFUSION_OCNOS = 54
    JUNIPER = 55
    JUNIPER_JUNOS = 56
    LINUX = 57
    MELLANOX = 58
    MRV_OPTISWITCH = 59
    NETAPP_CDOT = 60
    NETSCALER = 61
    OVS_LINUX = 62
    PALOALTO_PANOS = 63
    PLURIBUS = 64
    QUANTA_MESH = 65
    RAD_ETX = 66
    RUCKUS_FASTIRON = 67
    UBIQUITI_EDGE = 68
    UBIQUITI_EDGESWITCH = 69
    VYATTA_VYOS = 70
    VYOS = 71

    def __str__(self):
        return '{}'.format(self.value)

    @classmethod
    def values(cls):
        return cls.__members__.keys()

    @classmethod
    def value_of(cls, device_type):
        return cls.__members__[device_type]

    def to_lower_case(self):
        return self._name_.lower()
