#!/usr/bin/env python
# -*- coding: utf-8 -*-

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="protectwise-lib", # Replace with your own username
    version="0.0.2",
    author="5A4B48",
    author_email="pw@cybersecintel.ca",
    description="A python Library for interacting with Protectwise API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/5A4B48/protectwise-lib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.1',
)

