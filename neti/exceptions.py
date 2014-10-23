#
#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.
#


class NetiError(Exception):
    pass


class AddressValueError(NetiError):
    pass


class MetadataError(NetiError):
    pass


class MissingBinaryError(NetiError):
    pass


class InvalidIPtablesVersionError(NetiError):
    pass


class InvalidIPSetVersionError(NetiError):
    pass


class InvalidChainError(NetiError):
    pass


class InvalidIPError(NetiError):
    pass


class NoAvailableIPsError(NetiError):
    pass


class IPPatternMismatchError(NetiError):
    pass


class BadIPTablesError(NetiError):
    pass
