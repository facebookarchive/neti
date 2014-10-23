#!/usr/bin/env ruby
#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#

#
# Neti Packet Drop Check
#
# This Sensu plugin monitors the setting of the default packet drop.
#

require "rubygems" if RUBY_VERSION < "1.9.0"
require "sensu-plugin/check/cli"

class CheckVXCode < Sensu::Plugin::Check::CLI

  def run
      begin
        line = `sudo iptables -L -v | grep INPUT`
          if !line.scan(/DROP/)
              critical "Not dropping INPUT packets!"
          else
              ok "Dropping INPUT packets."
          end
      end
  end

end
