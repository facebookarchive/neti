import os
import sys

from ConfigParser import ConfigParser

config = ConfigParser()
if os.path.exists("/etc/neti/neti.conf"):
    config_file = "/etc/neti/neti.conf"
elif os.path.exists("testing.conf"):  # Assumes testing
    config_file = "testing.conf"
else:
    print "Could not load config file in /etc/neti/neti.conf or testing.conf"
    sys.exit(1)

config.read(config_file)
