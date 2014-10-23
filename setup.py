#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

from neti import __author__, __author_email__, __version__
from setuptools import setup

setup(name='neti',
      version=__version__,
      description="Zookeeper-based iptables firewall sync daemon",
      url="https://github.com/Instagram/neti",
      long_description=open('README.txt').read(),
      author=__author__,
      author_email=__author_email__,
      packages=['neti'],
      scripts=['bin/neti'],
      install_requires=[
          'PyYAML',
          'kazoo == 1.3.1',
          'requests == 0.11.2',
          'boto == 2.14.0',
          'ipaddress == 1.0.6'
      ]
      )
