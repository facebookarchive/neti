#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

import logging
import md5
import os
import re
import subprocess
import sys
import tempfile

import neti.constants as constants

from ipaddress import IPv4Network
from neti.exceptions import BadIPTablesError, InvalidIPtablesVersionError, InvalidIPSetVersionError, MissingBinaryError, InvalidChainError, InvalidIPError, AddressValueError
from shutil import copy2

logger = logging.getLogger('neti')


class IPtables(object):

    def __init__(self, config, is_vpc=False, dry_run=False):
        self._is_vpc = is_vpc
        self._get_all_binaries()
        self.legacy_ipset = True
        self._check_compatibility()
        self.dry_run = dry_run
        self.ssh_whitelist = config["ssh_whitelist"] or []
        self.open_ports = config["open_ports"] or []
        self.reject_all = config["reject_all"]
        self.table_files_path = config["table_files_path"]
        self.nat_overrides = config["nat_overrides"] or {}

    def _get_all_binaries(self):
        for binary in constants.BINARIES:
            self._get_binary(binary)

    def _get_binary(self, binary):
        try:
            setattr(self, "%s_bin" % binary.replace("-", "_"), subprocess.check_output(["which", binary]).strip())
        except subprocess.CalledProcessError:
            logger.error("No %s version found!" % binary)
            raise MissingBinaryError

    def _check_compatibility(self):
        """ Checks binary compatibility. """
        self._check_iptables_compatibility()
        self._check_ipset_compatibility()

    def _check_iptables_compatibility(self):
        """ Checks iptables binary compatibility. """
        try:
            iptables_version_string = subprocess.check_output([self.iptables_bin, "-V"])
        except subprocess.CalledProcessError:
            raise MissingBinaryError
        non_decimal = re.compile(r'[^\d.]+')
        version = non_decimal.sub('', iptables_version_string.split()[1])
        if tuple(version.split(".")) < (1, 2, 10):
            logger.error("iptables must be of version 1.2.10 or higher!")
            raise InvalidIPtablesVersionError

    def _check_ipset_compatibility(self):
        """ Checks ipset binary compatibility. """
        try:
            ipset_version_string = subprocess.check_output([self.ipset_bin, "-v"])
        except subprocess.CalledProcessError:
            raise MissingBinaryError
        version_match = re.compile(r'protocol version:? (\d)')
        res = version_match.search(ipset_version_string)
        if res:
            version = int(res.groups()[0])
            if version == 6:
                self.legacy_ipset = False
        else:
            logger.error("Cannot find ipset version!")
            raise InvalidIPSetVersionError

    def build(self, bundles):
        """ Gets nodes from ZK, builds rule table, and pushes it live. """
        self._check_compatibility()
        num_entries = len(bundles)
        logger.info("%d party members" % num_entries)
        if num_entries > 0:
            with tempfile.NamedTemporaryFile() as temp:
                self._gen_ipset_rules(temp, bundles)
                self._push_ipset_live(temp)
            for table in constants.TABLES:
                with tempfile.NamedTemporaryFile() as temp:
                    self._gen_rule_file(table, temp, bundles)
                    self._push_iptables_live(table, temp)

    def _gen_ipset_rules(self, temp, bundles):
        """ Writes the main ipset set (not caring about the return value...just making sure it's there)
            and builds the new set of IPs. """

        self._install_ipset(constants.IPSET_PROD)
        temp.write("%s\n" % self._gen_ipset(constants.IPSET_STAGING))
        ignore_str = "-! "
        if self.legacy_ipset:
            ignore_str = ""
        for bundle in bundles:
            temp.write("%s-A %s %s\n" % (ignore_str, constants.IPSET_STAGING, bundle.filter_ip(self._is_vpc)))
        temp.write("COMMIT\n")
        temp.flush()

    def _install_ipset(self, set_name):
        try:
            command = [self.ipset_bin] + self._gen_ipset(set_name).split()
            subprocess.check_output(command)
        except subprocess.CalledProcessError, e:
            if e.returncode != 1:
                logger.error("Error inserting ipset: %s" % e.output)

    def _gen_ipset(self, set_name):
        hashsize_opt = ""
        if "hash" in constants.IPSET_TYPE:
            hashsize_opt = "--hashsize %d" % constants.IPSET_HASHSIZE
        return "-N %s %s %s" % (set_name, constants.IPSET_TYPE, hashsize_opt)

    def _push_ipset_live(self, temp):
        """ Writes the new list to a staging set, atomically swaps the main and staging sets,
            and finally deletes the staging set. (Yes, it's ridiculous that it can't do this internally,
            but it's our best option) """

        try:
            temp.seek(0)
            subprocess.check_output([self.ipset_bin, "-R"], stdin=temp, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            logger.error("Error in ipset rule file: %s" % e.output.strip())
        try:
            subprocess.check_output([self.ipset_bin, "-W", constants.IPSET_STAGING, constants.IPSET_PROD])
        except subprocess.CalledProcessError, e:
            logger.error("Error swapping ipset rule file: %s" % e.output)
        try:
            subprocess.check_output([self.ipset_bin, "-X", constants.IPSET_STAGING])
        except subprocess.CalledProcessError, e:
            logger.error("Error deleting staging ipset rule file: %s" % e.output)

    def _gen_rule_file(self, table, temp, bundles):
        """ Generates rule file for the iptables-restore command. """
        temp.write(constants.IPTABLES_BASE[table])
        if table == "filter":
            for port in self.open_ports:
                if port:
                    temp.write("-A INPUT -p tcp --dport %s -m state --state NEW,ESTABLISHED -j ACCEPT\n" % port)
                    temp.write("-A OUTPUT -o eth0 -p tcp --sport %s -m state --state ESTABLISHED -j ACCEPT\n" % port)
            if self.reject_all:
                temp.write("-P INPUT DROP\n")
            else:
                temp.write("-P INPUT ACCEPT\n")
            if self._is_vpc:
                temp.write(str(FilterRule("INPUT", "10.0.0.0/8")))
            if len(self.ssh_whitelist) > 0:
                for ip in self.ssh_whitelist:
                    temp.write(str(FilterRule("ssh_whitelist", ip, dest_port=22)))

        elif table == "nat":
            for bundle in bundles:
                nat_ips = bundle.NAT_ips(self._is_vpc)
                temp.write(str(NATRule("OUTPUT", nat_ips["overlay_ip"], nat_ips["dest_ip"])))
            for src, dst in self.nat_overrides.iteritems():
                temp.write(str(NATRule("OUTPUT", src, dst)))

        temp.write("COMMIT\n")
        temp.flush()

    def _push_iptables_live(self, table, temp):
        """ Runs a syntax check on the IPtables rule file and loads it into the system if it passes.  If _dry_run
            is set, it prints the rule file to stdout. """

        temp.seek(0)
        current_table, update_table = self._table_needs_update(table, temp)
        if update_table:
            try:
                subprocess.check_output([self.iptables_restore_bin, "-t", temp.name])
            except subprocess.CalledProcessError, e:
                logger.error("Error in iptables rule file: %s" % e.output)
                raise BadIPTablesError(e.output)
            if self.dry_run:
                temp.seek(0)
                print temp.read()
                sys.exit(0)
            else:
                try:
                    subprocess.check_output([self.iptables_restore_bin, "-v", temp.name])
                    copy2(temp.name, current_table.name)
                except subprocess.CalledProcessError, e:
                    logger.error("Error in iptables rule file: %s" % e.output)

    def _table_needs_update(self, table, temp):
        update_table = True
        if not os.path.exists(self.table_files_path):
            os.makedirs(self.table_files_path)
        try:
            current_table = open("%s/%s" % (self.table_files_path, table), "r+")
            if self._tables_match(current_table, temp):
                logger.debug("%s table matches current...skipping" % table)
                update_table = False
        except IOError:
            current_table = open("%s/%s" % (self.table_files_path, table), "w")
        finally:
            current_table.close()
            return (current_table, update_table)

    def _tables_match(self, current_table, new_table):
        old = md5.new(current_table.read())
        new = md5.new(new_table.read())
        return old.digest() == new.digest()


class FilterRule(object):

    CHAINS = ["OUTPUT", "INPUT", "PREROUTING", "POSTROUTING", "ssh_whitelist", "ec2_whitelist"]

    def __init__(self, chain, source_ip, dest_port=None):
        self.chain = chain
        self.source_ip = source_ip
        self._validate()
        dport = ""
        if dest_port:
            dport = "-p tcp --dport %d" % dest_port
        self.rule = "-A %s -s %s %s -j ACCEPT\n" % (chain, self.source_ip, dport)

    def __str__(self):
        return self.rule

    def _validate(self):
        try:
            IPv4Network(unicode(self.source_ip))
        except AddressValueError:
            logger.error("Invalid IP specified in NAT rule!")
            raise InvalidIPError(self.source_ip)
        if self.chain not in self.CHAINS:
            logger.error("Invalid chain specified in NAT rule!")
            raise InvalidChainError(self.chain)


class NATRule(object):

    CHAINS = ["OUTPUT", "INPUT", "PREROUTING", "POSTROUTING"]

    def __init__(self, chain, source_ip, dest_ip):
        self.chain = chain
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self._validate()
        self.rule = "-A %s -d %s -j DNAT --to-destination %s\n" % (chain, self.source_ip, self.dest_ip)

    def __str__(self):
        return self.rule

    def _validate(self):
        for ip in [self.source_ip, self.dest_ip]:
            try:
                IPv4Network(unicode(ip))
            except AddressValueError:
                raise InvalidIPError(ip)
        if self.chain not in self.CHAINS:
            raise InvalidChainError(self.chain)
