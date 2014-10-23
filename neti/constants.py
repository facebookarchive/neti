#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

# Zookeeper
MAX_IP_TRIES = 5
ZK_TIMEOUT = 60
TIME_DELAY_MIN = 30
TIME_DELAY_MAX = 60
DEFAULT_SLEEP = 600
DEFAULT_MAX_CHANGE_THRESHOLD = 20
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
INSTANCE_ID_PATH = "instance-id"
PUBLIC_ADDRESS_PATH = "public-ipv4"
PRIVATE_ADDRESS_PATH = "local-ipv4"
MAC_PATH = "mac"
VPCID_PATH = "network/interfaces/macs/%s/vpc-id"
VPC_PUBLIC_ADDRESS_PATH = "network/interfaces/macs/%s/ipv4-associations/"

# IPtables
TABLES = ("filter", "nat")
BINARIES = ("iptables", "iptables-restore", "iptables-save", "ipset")
IPSET_PROD = "ec2_whitelist"
IPSET_STAGING = "staging"
IPTABLES_BASE = {}
IPTABLES_BASE["filter"] = """
*filter
-P FORWARD DROP
-N ssh_whitelist
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp ! --syn -m state --state NEW -j DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-I INPUT -m set --match-set %s src -j ACCEPT
-A INPUT -j ssh_whitelist
""" % IPSET_PROD
IPTABLES_BASE["nat"] = """
*nat
"""
IPSET_TYPE = "iphash"
IPSET_HASHSIZE = 8192
