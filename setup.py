#!/usr/bin/env python

from setuptools import setup

setup(
    setup_requires=['pbr'],
    pbr=True,
    include_package_data=True,
    package_data={
        '': ['*.md', '*.yml'],
    },
)
