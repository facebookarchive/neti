#!/usr/bin/env python
#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

#
# This syncs the Security groups between the EIPs for both the ZK and the ZK Proxy groups.
#

import os

from boto import connect_ec2
from boto.exception import EC2ResponseError

aws_key = os.environ["AWS_KEY"]
aws_secret = os.environ["AWS_SECRET"]

ZK_VPC_SEC_GROUP_ID = "sg-XXXXXXXX"
ZK_PROXY_SEC_GROUP_ID = "sg-XXXXXXXX"
ZK_PORT = 2181
ec2_conn = connect_ec2(aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)


def clean_old_ips(group, current_ips):
    print "Checking for old IPs in %s" % group.name
    to_remove = []
    for rule in group.rules:
        if rule.from_port and int(rule.from_port) == ZK_PORT and int(rule.to_port) == ZK_PORT:
            for grant in rule.grants:
                if grant.cidr_ip not in current_ips:
                    print "Removing %s" % grant.cidr_ip
                    to_remove.append(grant.cidr_ip)
            for cidr_ip in to_remove:
                group.revoke(ip_protocol=rule.ip_protocol, from_port=rule.from_port, to_port=rule.to_port, cidr_ip=cidr_ip)


def set_new_ips(group, current_ips):
    print "Setting %d IPs in %s..." % (len(current_ips), group.name)
    for ip in current_ips:
        try:
            group.authorize(ip_protocol="tcp", from_port=ZK_PORT, to_port=ZK_PORT, cidr_ip=ip)
        except EC2ResponseError:
            print "Duplicate: %s" % ip
            continue


def process_group(group, ips):
    clean_old_ips(group, ips)
    set_new_ips(group, ips)


def get_ips(group, filter_attr):
    print "Getting hosts for %s" % group.name
    filter = {"instance-state-name": "running", filter_attr: group.id}
    res = ec2_conn.get_all_instances(filters=filter)
    hosts = [r.instances[0] for r in res]
    cidrs = []
    for i in hosts:
        cidrs.append("%s/32" % i.ip_address)
    return cidrs


def get_group(id):
    print "Getting security group %s" % id
    return ec2_conn.get_all_security_groups(filters={"group-id": id})[0]


def main():
    zk_vpc_security_group = get_group(ZK_VPC_SEC_GROUP_ID)
    zk_proxy_security_group = get_group(ZK_PROXY_SEC_GROUP_ID)

    vpc_ips = get_ips(zk_vpc_security_group, "network-interface.group-id")
    ec2_ips = get_ips(zk_proxy_security_group, "group-id")

    process_group(zk_vpc_security_group, ec2_ips)
    process_group(zk_proxy_security_group, vpc_ips)

if __name__ == "__main__":
    main()
