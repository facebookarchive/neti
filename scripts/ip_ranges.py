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
import os
import time

from boto import connect_ec2
from boto.exception import EC2ResponseError

aws_key = os.environ["AWS_KEY"]
aws_secret = os.environ["AWS_SECRET"]

VPC_SEC_GROUP_ID = "sg-XXXXXXXX"
EC2_SEC_GROUP_ID = "sg-XXXXXXXX"
ec2_conn = connect_ec2(aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)

ranges = [
    "72.44.32.0/19",
    "67.202.0.0/18",
    "75.101.128.0/17",
    "174.129.0.0/16",
    "204.236.192.0/18",
    "184.73.0.0/16",
    "184.72.128.0/17",
    "184.72.64.0/18",
    "50.16.0.0/15",
    "50.19.0.0/16",
    "107.20.0.0/14",
    "23.20.0.0/14",
    "54.242.0.0/15",
    "54.234.0.0/15",
    "54.236.0.0/15",
    "54.224.0.0/15",
    "54.226.0.0/15",
    "54.208.0.0/15",
    "54.210.0.0/15",
    "54.221.0.0/16",
    "54.204.0.0/15",
    "54.196.0.0/15",
    "54.198.0.0/16"
]


def authorize_ips(group, current_ips, sleep):
    for ip in current_ips:
        try:
            print "Authorizing %s" % ip
            group.authorize(ip_protocol="tcp", from_port=0, to_port=65535, cidr_ip=ip)
            group.authorize(ip_protocol="udp", from_port=0, to_port=65535, cidr_ip=ip)
        except EC2ResponseError:
            print "Duplicate: %s" % ip
            continue
        time.sleep(sleep)


def revoke_ips(group, current_ips, sleep):
    for ip in current_ips:
        try:
            print "Revoking %s" % ip
            group.revoke(ip_protocol="tcp", from_port=0, to_port=65535, cidr_ip=ip)
            group.revoke(ip_protocol="udp", from_port=0, to_port=65535, cidr_ip=ip)
        except EC2ResponseError:
            print "Duplicate: %s" % ip
            continue
        time.sleep(sleep)


def get_group(id):
    return ec2_conn.get_all_security_groups(filters={"group-id": id})[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("side", type=str, choices=["ec2", "vpc"])
    parser.add_argument("--sleep", type=int, default=0, help="Number of seconds to sleep between rule authorizations")
    parser.add_argument("--revert", action='store_true', help="EMERGENCY ONLY: Remove all public IP ranges!")
    args = parser.parse_args()

    if args.side == "ec2":
        security_group = get_group(EC2_SEC_GROUP_ID)
    else:
        security_group = get_group(VPC_SEC_GROUP_ID)

    if args.revert:
        revoke_ips(security_group, ranges, args.sleep)
    else:
        authorize_ips(security_group, ranges, args.sleep)

if __name__ == "__main__":
    main()
