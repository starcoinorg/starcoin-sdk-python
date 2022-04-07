# SPDX-License-Identifier: Apache-2.0

import os
from setuptools import setup, find_packages

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
    long_description = f.read()

setup(
    name="starcoin-sdk-python",
    version="1.4.1",
    description="The Python Client SDK for Starcoin",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    url="https://github.com/fikgol/starcoin-sdk-python",
    python_requires=">=3.7",
    packages=find_packages('.'),
    package_dir={"": "./"},
    include_package_data=True,  # see MANIFEST.in
    zip_safe=True,
    install_requires=["requests>=2.20.0", "cryptography>=2.8", "numpy>=1.18"],
)
