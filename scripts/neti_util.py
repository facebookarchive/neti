#!/usr/bin/env python
#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

import argparse
import boto
import re

from kazoo.client import KazooClient
from ipaddress import IPv4Network
from prettytable import PrettyTable, PLAIN_COLUMNS

ZK_HOSTS = [
    "10.21.34.65:2181",
    "10.21.105.57:2181",
    "10.21.159.3:2181",
    "10.21.16.127:2181",
    "10.21.69.177:2181"
]

ZK_ROOT = "/neti"
ZK_IP_MAP = "%s/ip-map" % ZK_ROOT
ZK_IP_TO_ID = "%s/ip-to-id" % ZK_ROOT
IP_NETWORK = IPv4Network(unicode("192.168.0.0/18"))

conn = boto.connect_ec2()


def _try_int(s):
    try:
        return int(s)
    except:
        return s


def _natural_sorting_key(host):
    name = host.tags.get("Name") or host.public_dns_name
    return map(_try_int, re.findall(r"(\d+|\D+)", name))


def get_aws_instances():
    hostname_ignore = re.compile("^zkneti.*")
    instances = conn.get_only_instances(filters={"instance-state-name": "running"})
    instances = [i for i in instances if not hostname_ignore.match(i.tags.get("Name", ""))]
    return sorted(instances, key=_natural_sorting_key)


def get_neti_conn():
    zk = KazooClient(hosts=",".join(ZK_HOSTS))
    zk.start()
    return zk


def close_neti_conn(zk):
    zk.stop()
    zk.close()


def get_neti_used_ips(zk):
    ips = zk.get_children(ZK_IP_TO_ID)
    return ips


def get_neti_instances(zk):
    party_people = zk.get_children(ZK_IP_MAP)
    return [host.split("-")[1] for host in party_people]


def ver_str(version):
    if version:
        return tuple([int(i) for i in version.split(".")])
    else:
        return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--not-in-neti", dest="in_neti", action="store_false", help="Show only hosts not in Neti")
    parser.add_argument("--in-neti", dest="not_in_neti", action="store_false", help="Show only hosts in Neti")
    parser.add_argument("--below-version", dest="version", default=None, help="Show only hosts below specified version of Neti")
    parser.add_argument("--names-only", dest="names_only", action="store_true", help="Show only host names")
    parser.add_argument("--overlays-only", dest="overlays_only", action="store_true", help="Show only host names")
    parser.add_argument("--used-ips", dest="used_ips", action="store_true", help="Show only host names")
    args = parser.parse_args()

    zk = get_neti_conn()

    if args.used_ips:
        used_ips = get_neti_used_ips(zk)
        close_neti_conn(zk)
        used_count = len(used_ips)
        total_count = len(set(IP_NETWORK.hosts()))
        print "Used: %d; Total %d" % (used_count, total_count)
        return

    instances = get_aws_instances()
    neti_party = get_neti_instances(zk)
    close_neti_conn(zk)
    party_members = {m.split("|", 1)[0]: m.split("|") for m in neti_party}

    total_instance_count = len(instances)
    total_in_neti = len(neti_party)
    table = PrettyTable(["Name", "Public IP", "Private IP", "Overlay IP", "Neti Version", "VPC?"])
    table.set_style(PLAIN_COLUMNS)
    table.align = "l"
    for i in instances:
        if party_members.get(i.ip_address) and args.in_neti:
            if not args.version or ver_str(args.version) > ver_str(i.tags.get('neti_version')):
                public, private, overlay, vpc = party_members[i.ip_address]
                table.add_row([i.tags.get('Name'), public, private, overlay, i.tags.get('neti_version'), True if vpc == "1" else False])
        elif not party_members.get(i.ip_address) and args.not_in_neti:
            table.add_row([i.tags.get('Name'), i.ip_address, i.private_ip_address, None, None, True if i.vpc_id else False])
    if args.overlays_only:
        table.header = False
        print table.get_string(fields=["Overlay IP"])
    else:
        print table
        print "%d total instances, %d instances in Neti (%.0f%%)" % (total_instance_count,
                                                                     total_in_neti, 100 * float(total_in_neti) / float(total_instance_count))


if __name__ == "__main__":
    main()
