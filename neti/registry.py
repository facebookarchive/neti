#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

import boto
import logging
import random
import re
import requests

import neti.constants as constants

from ipaddress import AddressValueError, IPv4Address, IPv4Network
from kazoo.client import KazooClient, KazooState
from kazoo.exceptions import NodeExistsError, NoNodeError, ZookeeperError
from kazoo.recipe.party import ShallowParty
from kazoo.recipe.watchers import ChildrenWatch
from neti import __version__ as version
from neti.exceptions import IPPatternMismatchError, MetadataError, NoAvailableIPsError
from neti.iptables import IPtables

logger = logging.getLogger('neti')
kazoo_logger = logging.getLogger('kazoo')


class Connection(object):

    def __init__(self, config, dry_run=False):
        if self._is_vpc:
            self.zk_hosts = config["zk_hosts"]["vpc"]
        else:
            self.zk_hosts = config["zk_hosts"]["ec2"]
        self.zk = KazooClient(hosts=",".join(self.zk_hosts), timeout=constants.ZK_TIMEOUT, logger=kazoo_logger)
        self.aws_access_key_id = config["aws_key"]
        self.aws_secret_access_key = config["aws_secret_key"]
        self.overlay_subnet = config["overlay_subnet"]
        self.network = IPv4Network(unicode(self.overlay_subnet))
        self.instance_id = self._get_instance_id()
        self.public_ip = self._get_public_ip()
        self.private_ip = self._get_private_ip()

        try:
            self.zk.start()
            self.connected = True
            self.lost = False
        except self.zk.handler.timeout_exception:
            logger.error("Timed out connecting to Zookeeper.")

    def _get_metadata(self, path):
        if not path:
            raise "Metadata path cannot be empty!"
        res = requests.get("%s%s" % (constants.METADATA_URL, path))
        if res.status_code == 200:
            return str(res.text)
        else:
            raise MetadataError("Unable to get %s" % path)

    @property
    def _is_vpc(self):
        try:
            self._get_metadata(constants.VPCID_PATH % self._get_mac())
            return True
        except MetadataError:
            return False

    def _get_mac(self):
        return self._get_metadata(constants.MAC_PATH)

    def _get_instance_id(self):
        return self._get_metadata(constants.INSTANCE_ID_PATH)

    def _get_public_ip(self):
        try:
            return self._get_metadata(constants.PUBLIC_ADDRESS_PATH)
        except MetadataError:
            return self._get_metadata(constants.VPC_PUBLIC_ADDRESS_PATH % self._get_mac())

    def _get_private_ip(self):
        return self._get_metadata(constants.PRIVATE_ADDRESS_PATH)

    def tag_instance(self, data):
        try:
            ec2 = boto.connect_ec2(aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key)
            if not ec2.create_tags([self.instance_id], data):
                logger.error("Could not tag instance with %s" % data)
        except boto.exception.BotoServerError, e:
            logger.error("Could not tag instance due to boto error: %s" % e)


class Registry(object):

    def __init__(self, config, conn, dry_run=False):
        self.config = config
        self.zk_prefix = self.config["zk_prefix"]
        self.zk_iptoid_path = "%s/%s" % (self.zk_prefix, self.config["zk_iptoid_node"])
        self.zk_idtoip_path = "%s/%s" % (self.zk_prefix, self.config["zk_idtoip_node"])
        self.zk_ip_map_path = "%s/%s" % (self.zk_prefix, self.config["zk_ip_map_node"])
        self.zk_max_change_threshold_path = "%s/%s" % (self.zk_prefix, self.config["zk_max_change_threshold_path"])
        self.conn = conn
        self.dry_run = dry_run

    @property
    def _zk_id_path(self):
        """ :returns: ID to IP mapping path for this instance. """
        return "%s/%s" % (self.zk_idtoip_path, self.conn.instance_id)

    def _zk_ip_path(self, ip):
        """ :returns: IP to ID mapping path for this IP. """
        return "%s/%s" % (self.zk_iptoid_path, ip)

    def _tag_instance(self):
        """ Tag "overlay_ip" and "neti_version" on instance with registered overlay_ip """
        self.conn.tag_instance({"overlay_ip": self.overlay_ip, "neti_version": version})

    def _choose_overlay_ip(self):
        """
        Get list of used IPs from ZK and randomly choose one from the rest of the subnet.
        :returns: String containing chosen IP.
        """
        try:
            used_ips = {IPv4Address(unicode(ip)) for ip in self.conn.zk.get_children(self.zk_iptoid_path)}
        except NoNodeError:
            used_ips = set()
        available_ips = set(self.conn.network.hosts()) - used_ips
        if not available_ips:
            logger.error("No available IPs found!")
            raise NoAvailableIPsError
        return str(random.sample(available_ips, 1)[0])

    def _find_available_overlay_ip(self):
        """
        Get a new IP, and attempt to register it.  If it already is taken, get another.  Retry this cycle for
        MAX_RETRIES. After that, fail on no IPs.
        :returns: String containing overlay IP.
        """
        retries = 0
        ip = self._choose_overlay_ip()
        while retries < constants.MAX_IP_TRIES:
            retries += 1
            try:
                self.conn.zk.create(self._zk_id_path, ip)
                logger.warn("Creating %s" % ip)
            except NoNodeError:
                self.conn.zk.ensure_path(self.zk_idtoip_path)
                logger.error("Path %s did not exist...creating and trying again" % self.zk_idtoip_path)
                continue
            except NodeExistsError:
                try:
                    zk_ip, _ = self.conn.zk.get(self._zk_id_path)
                    logger.error("IP %s already assigned to %s...using that" % (zk_ip, self.conn.instance_id))
                except NoNodeError:
                    logger.error("No IP found...trying again")
                    continue
                return zk_ip
            try:
                zk_ip, _ = self.conn.zk.get(self._zk_id_path)
            except NoNodeError:
                logger.error("IP %s did not get associated...trying again" % ip)
                continue
            if zk_ip == ip:
                logger.info("IP %s set" % ip)
                return ip
            else:
                logger.error("IP %s already assigned to %s...using that" % (zk_ip, self.conn.instance_id))
                return zk_ip

        logger.error("No available IPs found!")
        raise NoAvailableIPsError

    def _set_ip_to_id_map(self, ip):
        """ Sets the reverse map for IP-based lookups. """
        try:
            self.conn.zk.set(self._zk_ip_path(ip), self.conn.instance_id)
        except NoNodeError:
            logger.info("No IP to ID map node for %s" % ip)
            try:
                self.conn.zk.create(self._zk_ip_path(ip), self.conn.instance_id)
            except NoNodeError:
                self.conn.zk.ensure_path(self._zk_ip_path(ip))
                self._set_ip_to_id_map(ip)

    def register(self):
        """ Attempt to get registered overlay IP by instance ID.  If that succeeds, verify that the IP to ID map
        is set correctly, set the instance variable, and tag the instance.  If it fails, attempt to get a new one.
        :returns: String containing overlay IP. """
        try:
            self.overlay_ip, _ = self.conn.zk.get(self._zk_id_path)
        except NoNodeError:
            self.overlay_ip = self._find_available_overlay_ip()
        self.conn.zk.handler.spawn(self._tag_instance)
        self._set_ip_to_id_map(self.overlay_ip)
        return self.overlay_ip

    def _get_ip_map(self):
        """ :returns: Mapping of all IPs for znode """
        return "%s|%s|%s|%d" % (self.conn.public_ip, self.conn.private_ip, self.overlay_ip, self.conn._is_vpc)

    def _ips_from_entries(self, entries):
        """ Builds array of InstanceIPBundles from found ZK nodes.
            :returns: List of InstanceIPBundles. """
        ips = []
        for entry in entries:
            ips.append(InstanceIPBundle(entry))
        return ips

    def _join_party(self):
            self.party = ShallowParty(self.conn.zk, self.zk_ip_map_path, identifier=self._get_ip_map())
            self.party.join()

    def _load_param(self, path, default):
        try:
            param, _ = self.conn.zk.retry(self.conn.zk.get, path)
            return int(param) if param else default
        except NoNodeError:
            self.conn.zk.ensure_path(path)
            self.conn.zk.retry(self.conn.zk.set, (path, str(default)))
            return default

    def _state_listener(self, state):
        logger.error("Connection state change: %s" % state)
        if state == KazooState.SUSPENDED:
            logger.warn("Suspended connection, setting connected to False.")
            self.conn.connected = False
        elif state == KazooState.LOST:
            logger.warn("Lost connection, setting lost to True.")
            self.conn.lost = True
            self.conn.zk.handler.spawn(self._rejoin_party)
        elif state == KazooState.CONNECTED:
            logger.warn("Regained connection, setting connected to True.")
            self.conn.connected = True
            self.conn.zk.handler.spawn(self._rejoin_party)

    def _rejoin_party(self):
        logger.warn("Thinking about going back to the party (Lost: %r; Connected %r)..." % (self.conn.lost, self.conn.connected))
        if self.conn.lost and self.conn.connected:
            logger.warn("Got 86'd. Sneaking back into the party...")
            self._join_party()
            self.conn.lost = False

    def run(self):
        """ Connects to both ZKs, inserts an ephemeral node, and starts a watch for changes. """
        try:
            self._join_party()
            self.conn.zk.add_listener(self._state_listener)

            @ThrottledChildrenWatch(self.conn.zk, self.zk_ip_map_path, delay_min=constants.TIME_DELAY_MIN, delay_max=constants.TIME_DELAY_MAX)
            def update_iptables(hosts):
                self.max_change_threshold = self._load_param(self.zk_max_change_threshold_path, constants.DEFAULT_MAX_CHANGE_THRESHOLD)
                if getattr(self, "hosts", None):
                    hosts_to_remove = len(self.hosts) - len(hosts)
                    if hosts_to_remove > self.max_change_threshold:
                        logger.warn("Trying to remove %d hosts...untriggering (max is %s)" % (hosts_to_remove, self.max_change_threshold))
                        return
                    else:
                        remove = set(self.hosts) - set(hosts)
                        add = set(hosts) - set(self.hosts)
                        if add:
                            logger.debug("Adding: %s" % add)
                        if remove:
                            logger.debug("Removing: %s" % remove)
                self.hosts = hosts
                bundles = self._ips_from_entries(self.hosts)
                builder = IPtables(config=self.config, is_vpc=self.conn._is_vpc, dry_run=self.dry_run)
                builder.build(bundles)

            while True:
                self.conn.zk.handler.sleep_func(constants.DEFAULT_SLEEP)

        except ZookeeperError as e:
            logger.error("ZookeeperError: %s" % e)
            self.run()


class ThrottledChildrenWatch(ChildrenWatch):

    def __init__(self, *args, **kwargs):
        self.delay_min = kwargs.pop("delay_min", constants.TIME_DELAY_MIN)
        self.delay_max = kwargs.pop("delay_max", constants.TIME_DELAY_MAX)
        super(ThrottledChildrenWatch, self).__init__(*args, **kwargs)
        self.triggered = False

    def _watcher(self, event):
        logger.debug("Watcher received")
        if not self.triggered:
            try:
                time_to_wait = random.randint(self.delay_min, self.delay_max)
                logger.debug("Watcher triggered, sleeping for %d seconds" % time_to_wait)
                self.triggered = True
                self._client.handler.sleep_func(time_to_wait)
                self._get_children(event)
            finally:
                self.triggered = False
        return


class InstanceIPBundle(object):
    """ Bundle object that holds all associated IPs for an instance. """

    uuid_delim = "-"
    ip_delim = "|"
    ip_labels = ["public_ip", "private_ip", "overlay_ip"]

    def __init__(self, entry):
        self.entry = entry
        self._parse_entry()

    def NAT_ips(self, is_vpc):
        """ :returns: dict of IPs needed for NAT rule. """
        ips = {"overlay_ip": self.overlay_ip}
        ips["dest_ip"] = self.private_ip if is_vpc == int(self.is_vpc) else self.public_ip
        return ips

    def filter_ip(self, is_vpc):
        """ :returns: IP string needed for filter rule. """
        if is_vpc == int(self.is_vpc):
            return self.private_ip
        return self.public_ip

    def _parse_entry(self):
        """ Matches ZK node to pattern and sets all IP instance variables. """
        try:
            _, ip_string = self.entry.split(self.uuid_delim)
        except ValueError:
            logger.error("Invalid ZK entry %s" % self.entry)
            raise IPPatternMismatchError(self.entry)
        binary_check = re.compile('[01]')
        try:
            self.is_vpc = ip_string.rsplit(self.ip_delim, 1)[1]
        except ValueError:
            logger.error("Invalid ZK entry %s" % self.entry)
            raise IPPatternMismatchError(self.entry)
        if not binary_check.match(self.is_vpc):
            raise IPPatternMismatchError(self.entry)
        try:
            ips = dict(zip(self.ip_labels, ip_string.split(self.ip_delim)))
        except ValueError:
            logger.error("Invalid ZK entry %s" % self.entry)
            raise IPPatternMismatchError(self.entry)
        if len(ips) != len(self.ip_labels):
            logger.error("Invalid ZK entry %s" % self.entry)
            raise IPPatternMismatchError(self.entry)

        for label, ip in ips.iteritems():
            try:
                IPv4Network(unicode(ip))
            except AddressValueError:
                logger.error("Invalid IP found - %s:%s" % (label, ip))
                raise IPPatternMismatchError(self.entry)
            else:
                setattr(self, label, ip)
