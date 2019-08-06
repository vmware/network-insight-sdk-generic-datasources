# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import os
import network_insight_sdk_generic_datasources.common.yaml_utilities as yaml_utilities
from network_insight_sdk_generic_datasources.archive.zip_archiver import ZipArchiver

from network_insight_sdk_generic_datasources.common.constants import TABLE_JOINERS_KEY
from network_insight_sdk_generic_datasources.common.constants import WORKLOADS_KEY
from network_insight_sdk_generic_datasources.common.constants import PACKAGE_HANDLER_KEY
from network_insight_sdk_generic_datasources.common.constants import RESULT_WRITER_KEY
from network_insight_sdk_generic_datasources.common.constants import GENERATION_DIRECTORY_KEY


def parse_arguments():
    parser = argparse.ArgumentParser(description='Collect cli data from physical device')
    parser.add_argument('-d', '--device', action='store', help='Physical Device Type e.g. Cisco')
    parser.add_argument('-m', '--model', action='store', help='Physical Device model e.g. N5k')
    parser.add_argument('-s', '--device_type', action='store', help='Software installed on device')
    parser.add_argument('-i', '--ip_or_fqdn', action='store', help='IP or FQDN')
    parser.add_argument('-u', '--username', action='store', help='Username for login')
    parser.add_argument('-p', '--password', action='store', help='Password for login')
    parser.add_argument('-z', '--self_zip', action='store', help='Self Zip the Project', default='false')
    parser.add_argument('-P', '--port', action='store', help='Specific port to connect', default='22')
    parser.add_argument('-o', '--output_zip', action='store', help='Output zip file to create with CSVs')
    args = parser.parse_args()
    return args


def main():
    import common.physical_device as physical_device
    args = parse_arguments()
    dir_path = "routers_and_switches/{}".format(args.device)
    # yaml_definition_file_name = "{}_{}_command_map.yml".format(args.device, args.model)
    yaml_definition_file_name = "{}.yml".format(args.device)
    self_zip = True if args.self_zip == 'true' or args.self_zip == 'True' else False
    with open("%s%s%s%s%s" % (os.path.dirname(__file__), os.path.sep,
                              dir_path,
                              os.path.sep,
                              yaml_definition_file_name)) as f:
        configuration = yaml_utilities.altered_safe_load(f)
        table_joiner = configuration[args.model][TABLE_JOINERS_KEY] if TABLE_JOINERS_KEY in configuration[
            args.model] else None
        generation_directory = configuration[GENERATION_DIRECTORY_KEY] + '/' + args.ip_or_fqdn
        physical_device = physical_device.PhysicalDevice(args.device, args.model,
                                                         configuration[args.model][WORKLOADS_KEY],
                                                         args,
                                                         table_joiner,
                                                         configuration[args.model][RESULT_WRITER_KEY],
                                                         generation_directory)
        physical_device.process()
        if PACKAGE_HANDLER_KEY in configuration:
            zipper = ZipArchiver(self_zip, args.output_zip, generation_directory)
            zipper.zipdir()


if __name__ == "__main__":
    main()
