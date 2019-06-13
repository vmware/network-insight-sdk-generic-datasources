# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import logging
import tempfile
import os

DEFAULT_LOG_PATH = "%stmp%s" % (os.path.sep, os.path.sep)

logging.basicConfig(filename='/tmp/third-party-sdk.log', format='%(levelname)s %(asctime)s %(message)s',
                    datefmt='[%m/%d/%Y %I:%M:%S %p]', filemode='a', level=logging.INFO)


def get_log_file_path(file_name=None, prefix=None):

    file_path = DEFAULT_LOG_PATH
    if file_name:
        tmp_file = "%s%s%s" % (file_path, os.sep, file_name)

    else:
        tmp_file = tempfile.mktemp(prefix=(prefix, "")[prefix is None],
                                   dir=file_path,
                                   suffix=".log")
    return tmp_file


def configure_logger(file_name=None):
    tmp_file = get_log_file_path(file_name, prefix="third_party_sdk_")
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-20s: %(levelname)-8s: %(message)s',
                        datefmt='[%m-%d %H:%M:%S]',
                        filename=tmp_file,
                        filemode='w')
    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)

    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s:  %(filename)-15s: %(lineno)-4d %(levelname)-8s: %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger().addHandler(console)
    py_logger = logging.getLogger()

    py_logger.critical("Log file Name: %s", tmp_file)

    return py_logger


py_logger = configure_logger()

