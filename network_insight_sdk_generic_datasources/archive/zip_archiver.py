# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause

import os
import zipfile
from shutil import copyfile
from network_insight_sdk_generic_datasources.common.log import py_logger
from network_insight_sdk_generic_datasources.common.constants import CSV_EXTENSION


class ZipArchiver(object):
    """
    Utility for creating zip file out of a directory containing other files.
    """
    def __init__(self, self_zip=False, filename=None, path=None, expected_filenames=None):
        if path is None:
            raise ValueError("Invalid Path. Please provide path.")
        if filename is None:
            raise ValueError("Invalid filename. Please provide zip filename")
        if path.strip() == '':
            raise ValueError("Invalid Path. Please provide path.")
        if filename.strip() == '':
            raise ValueError("Invalid filename. Please provide zip filename")
        self.self_zip = self_zip
        self.path = path
        self.filename = filename
        self.expected_filenames = []
        for f in expected_filenames:
            self.expected_filenames.append(f + CSV_EXTENSION)

    def zipdir(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        if not os.path.exists(self.path):
            py_logger.error("Couldn't create directory {}. Please check permissions.".format(self.path))
            return

        self.copy_project_base()
        zipfile_path, zipfile_name = os.path.split(os.path.abspath(self.filename))
        zip_file_path = '{}/{}'.format(zipfile_path, zipfile_name)
        zipf = zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(self.path):
            for f in files:
                if f in self.expected_filenames:
                    zipf.write(os.path.join(root, f))
        zipf.close()

    def copy_project_base(self):
        if not self.self_zip:
            return
        # Copy All the files in destination path
        for dir, dir_name, files in os.walk(os.path.curdir + '/..'):
            destination = self.path + dir.replace('./..', '/sdk')
            if not os.path.exists(destination):
                os.makedirs(destination)
                for f in files:
                    if '.pyc' in f:
                        continue
                    copyfile(dir + '/' + f, destination + '/' + f)


if __name__ == '__main__':
    zipper = ZipArchiver('/tmp/mydir', 'myfile.zip')
    zipper.zipdir()
