#!/usr/bin/python

import asyncio
import asyncudp
import asyncio_dgram
import logging
from enum import Enum

from construct import ConstructError, Struct, Int8ub, Int16ub, Int32ub, Optional, Const, Bytes, Padding, this, \
  PascalString, VarInt

LOG = logging.getLogger("tunneldigger.protocol")

# Control message for our protocol; first few bits are special as we have to
# maintain compatibility with LTPv3 in the kernel (first bit must be 1); also
# the packet must be at least 12 bytes in length, otherwise some firewalls
# may filter it when used over port 53
ControlMessage = Struct(
    # Ensure that the first bit is 1 (L2TP control packet)
    "magic1" / Const(0x80, Int8ub),
    # Reduce conflict matching to other protocols as we run on port 53
    "magic2" / Const(0x73A7, Int16ub),
    # Protocol version to allow future upgrades
    "version" / Int8ub,
    # Message type
    "type" / Int8ub,
    # Message data (with length prefix)
    "data_size" / Int8ub,
    "data" / Bytes(this.data_size),
    # Pad the message so it is at least 12 bytes long
    Optional(Padding(lambda ctx: max(0, 6 - len(ctx["data"])))),
)


class PDUTypes(Enum):
    CONTROL_TYPE_COOKIE = 0x01
    CONTROL_TYPE_PREPARE = 0x02
    CONTROL_TYPE_ERROR = 0x03
    CONTROL_TYPE_TUNNEL = 0x04
    CONTROL_TYPE_KEEPALIVE = 0x05
    CONTROL_TYPE_PMTUD = 0x06
    CONTROL_TYPE_PMTUD_ACK = 0x07
    CONTROL_TYPE_REL_ACK = 0x08
    CONTROL_TYPE_PMTUD_NTFY = 0x09
    CONTROL_TYPE_USAGE = 0x0A
    CONTROL_TYPE_LIMIT = 0x80


# Error Reason Byte
# e.g. a client shutdown. it sends 0x11 to the server which answer with 0x00 (other request)
# left nibble is direction
class PDUError(Enum):
    # right nibble is error code
    ERROR_REASON_OTHER_REQUEST = 0x01  # other site requested
    ERROR_REASON_SHUTDOWN = 0x02  # shutdown
    ERROR_REASON_TIMEOUT = 0x03
    ERROR_REASON_FAILURE = 0x04  # e.q. on malloc() failure
    ERROR_REASON_UNDEFINED = 0x05


class PDUDirection(Enum):
    ERROR_REASON_FROM_SERVER = 0x00
    ERROR_REASON_FROM_CLIENT = 0x10


CookieMessage = Struct(
    "cookie" / Bytes(8)
)

# Prepare message
PrepareMessage = Struct(
    "cookie" / Bytes(8),
    "uuid" / PascalString(VarInt, 'utf8'),
    "tunnel_id" / Optional(Int32ub),
    "features" / Optional(Int32ub)
)

# Error message
ErrorMessage = Struct(
    "error" / Int8ub,
)

TunnelMessage = Struct(
    "tunnel_id" / Int32ub,
    "features" / Optional(Int32ub)
)

KeepAliveMessage = Struct(
    "sequence" / Int32ub,
)

PMTUNotifyMessage = Struct(
    "pmtu" / Int16ub
)

PMTUMessage = Struct(
    # the data size is 0 on PMTU messages
    "bytes" / Bytes(32),
    Optional(Padding(lambda ctx: max(0, 6 - len(ctx["data"])))),
)

# When a PMTUMessage has been received, an Ack with the size is sent back. pmtu is UDP data size (excluding IP + UDP hdr)
PMTUAckMessage = Struct(
    "pmtu" / Int16ub,
)

ReliableAckMessage = Struct(
    "sequence" / Int16ub,
)

# Usage to ask a server of it's usage
# cli -> server: usage with dummy content, features with client features
# server -> cli: usage with a real value, features of the server
UsageMessage = Struct(
    "usage" / Int8ub,
    "features" / Optional(Int32ub)
)

# Limit message
LimitMessage = Struct(
    "sequence" / Int16ub,
    # Limit type
    "type" / Int8ub,
    "config_len" / Int8ub,
    # so far only bandwidth is supported (Int32ub)
    "config" / Bytes(this.config_len),
)

LimitBandwidth = Struct(
    "bandwidth" / Int32ub,
)

PDUS = {
    PDUTypes.CONTROL_TYPE_COOKIE: CookieMessage,
    PDUTypes.CONTROL_TYPE_PREPARE: PrepareMessage,
    PDUTypes.CONTROL_TYPE_ERROR: ErrorMessage,
    PDUTypes.CONTROL_TYPE_TUNNEL: TunnelMessage,
    PDUTypes.CONTROL_TYPE_KEEPALIVE: KeepAliveMessage,
    PDUTypes.CONTROL_TYPE_PMTUD: PMTUMessage,
    PDUTypes.CONTROL_TYPE_PMTUD_ACK: PMTUAckMessage,
    PDUTypes.CONTROL_TYPE_REL_ACK: ReliableAckMessage,
    PDUTypes.CONTROL_TYPE_PMTUD_NTFY: PMTUNotifyMessage,
    PDUTypes.CONTROL_TYPE_USAGE: UsageMessage,
    PDUTypes.CONTROL_TYPE_LIMIT: LimitMessage,
}

LIMIT_TYPE_BANDWIDTH_DOWN = 0x01
FEATURE_UNIQUE_SESSION_ID = 0x01

# Overhead of IP and UDP headers for measuring PMTU
IPV4_HDR_OVERHEAD = 28

# L2TP data header overhead for calculating tunnel MTU; takes
# the following headers into account:
#
#   20 bytes (IP header)
#    8 bytes (UDP header)
#    4 bytes (L2TPv3 Session ID)
#    4 bytes (L2TPv3 Cookie)
#    4 bytes (L2TPv3 Pseudowire CE)
#   14 bytes (Ethernet)
#
L2TP_TUN_OVERHEAD = 54

# Control header overhead for a zero-length payload
L2TP_CONTROL_SIZE = 6

# Ioctls
SIOCSIFMTU = 0x8922

# Socket options
IP_MTU_DISCOVER = 10
IP_PMTUDISC_PROBE = 3
SO_BINDTODEVICE = 25

TD_MIN_PDU_LEN = 4

class TunneldiggerProtocol(asyncio.DatagramProtocol):
    def __init__(self, tunnelmanager, tunnel):
        self.tunnelmanager = tunnelmanager
        self.tunnel = tunnel
        self.socket = None

    def _disconnect(self):
        self.socket.close()
        self.socket = None
        if self.tunnel:
            asyncio.create_task(self.tunnelmanager.close_tunnel(self.tunnel))

    async def sock_loop(self):
        # ensure self.socket is present before calling sock_loop()
        while True:
            try:
                data, addr = await self.socket.recv()
                await self.datagram_received(data, addr)
            except OSError as exp:
                if exp.errno == 90:
                    # ignore Message too long exception
                    continue
                elif exp.errno == 111:
                    # Connection refused
                    return self._disconnect()
                else:
                    raise
            except asyncio_dgram.aio.TransportClosed:
                return self._disconnect()

    async def _send(self, data, endpoint):
        if self.socket is None:
            return
        try:
            if self.tunnel:
                await self.socket.send(data)
            else:
                await self.socket.send(data, endpoint)
        except OSError as err:
            if err.errno == 111:
                # connection refused
                return self._disconnect()
            raise

    async def tx_control(self, endpoint, pdu_type, data: bytes):
        control = ControlMessage.build(dict(version=1, type=pdu_type.value, data_size=len(data), data=data))
        await self._send(control, endpoint)

    async def tx_usage(self, endpoint, usage, features=None):
        pdu = UsageMessage.build(dict(usage=usage, features=features))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_USAGE, pdu)

    async def tx_cookie(self, endpoint, cookie):
        pdu = CookieMessage.build(dict(cookie=cookie))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_COOKIE, pdu)

    async def tx_error(self, endpoint, error):
        pdu = ErrorMessage.build(dict(error=error))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_ERROR, pdu)

    async def tx_tunnel(self, endpoint, tunnel_id, features=None):
        pdu = TunnelMessage.build(dict(tunnel_id=tunnel_id, features=features))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_TUNNEL, pdu)

    async def tx_keepalive(self, endpoint, sequence):
        pdu = KeepAliveMessage.build(dict(sequence=sequence))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_KEEPALIVE, pdu)

    async def tx_pmtu(self, endpoint, size):
        control = ControlMessage.build(dict(version=1, type=PDUTypes.CONTROL_TYPE_PMTUD.value, data_size=0, data=b''))
        control += b'\x00' * (size - IPV4_HDR_OVERHEAD - L2TP_CONTROL_SIZE - 6)
        await self._send(control, endpoint)

    async def tx_pmtuack(self, endpoint, pmtu):
        pdu = PMTUAckMessage.build(dict(pmtu=pmtu))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_PMTUD_ACK, pdu)

    async def tx_pmtunotify(self, endpoint, pmtu):
        pdu = PMTUNotifyMessage.build(dict(pmtu=pmtu))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_PMTUD_NTFY, pdu)

    async def tx_relack(self, endpoint, sequence):
        pdu = ReliableAckMessage.build(dict(sequence=sequence))
        await self.tx_control(endpoint, PDUTypes.CONTROL_TYPE_REL_ACK, pdu)

    async def rx_unknown(self, endpoint, data):
        return self.packet_error(None, "Ignoring Error PDU %s" % str(endpoint), data)

    def connection_made(self, transport):
        self.socket = transport

    def packet_error(self, tunnel, message: str, data: bytes):
        # TODO: allow to hexdump data when a flag/config is enabled
        message += " " + str(data)
        if tunnel:
            LOG.debug("%s: %s", tunnel, message)
        else:
            LOG.debug(message)

    def connection_lost(self, exc):
        LOG.error("Lost UDP connection!")
        if self.tunnel:
            asyncio.create_task(self.tunnelmanager.close_tunnel(self.tunnel))

    async def datagram_received(self, data, endpoint):
        """Called when some datagram is received."""
        if self.tunnelmanager is None or self.tunnelmanager.closed:
            return

        tunnel = self.tunnel or self.tunnelmanager.get_tunnel(endpoint)
        if len(data) < TD_MIN_PDU_LEN:
            self.packet_error(tunnel, "Packet too small", data)
            return

        try:
            control = ControlMessage.parse(data)
        except ConstructError:
            self.packet_error(tunnel, "Invalid packet received", data)
            return
        try:
            pdu_type = PDUTypes(control.type)
        except ValueError:
            LOG.debug("Rx %s, %s/%s", control.type, self, self.tunnel)
            self.packet_error(tunnel, "Invalid PDU type 0x%x" % control.type, data)
            return

        # PMTUD are special because they don't have a payload
        if pdu_type == PDUTypes.CONTROL_TYPE_PMTUD:
            if tunnel:
                await tunnel.rx_pmtu(data)
            return

        try:
            pdu = PDUS[pdu_type].parse(control.data)
        except Exception as exp:
            self.packet_error(tunnel, "Failed to parse PDU type %x." % control.type, data)
            LOG.debug("Exception while parsing pdu type %s", pdu_type, exc_info=True)
            return

        if tunnel:
            tunnel_pdu = {
                PDUTypes.CONTROL_TYPE_KEEPALIVE: tunnel.rx_keepalive,
                PDUTypes.CONTROL_TYPE_PMTUD_ACK: tunnel.rx_pmtuack,
                PDUTypes.CONTROL_TYPE_PMTUD_NTFY: tunnel.rx_pmtunotify,
                PDUTypes.CONTROL_TYPE_ERROR: tunnel.rx_error,
            }

            if pdu_type in tunnel_pdu:
                return await tunnel_pdu[pdu_type](pdu)
            elif pdu_type == PDUTypes.CONTROL_TYPE_LIMIT:
                if pdu.type == LIMIT_TYPE_BANDWIDTH_DOWN:
                    try:
                        config_pdu = LimitBandwidth.parse(pdu.config)
                    except Exception as exp:
                        self.packet_error(tunnel, "Failed to parse Limit type %x" % pdu.type, data)
                        LOG.debug("While parsing LimitMessage %s", pdu.type, exc_info=True)
                    return await tunnel.rx_limit(pdu, config_pdu)

        invalid_without_tunnel = [
            PDUTypes.CONTROL_TYPE_KEEPALIVE,
            PDUTypes.CONTROL_TYPE_PMTUD_ACK,
            PDUTypes.CONTROL_TYPE_PMTUD_NTFY,
            PDUTypes.CONTROL_TYPE_LIMIT,
        ]

        if not tunnel and pdu_type in invalid_without_tunnel:
            await self.tunnelmanager.unknown_tunnel(endpoint)
            return self.packet_error(tunnel, "Received %s without an assosiated tunnel." % pdu_type, data)

        tunnel_manager_pdu = {
            PDUTypes.CONTROL_TYPE_USAGE: self.tunnelmanager.usage,
            PDUTypes.CONTROL_TYPE_COOKIE: self.tunnelmanager.issue_cookie,
            PDUTypes.CONTROL_TYPE_PREPARE: self.tunnelmanager.prepare,
            PDUTypes.CONTROL_TYPE_ERROR: self.rx_unknown,
        }

        if pdu_type in tunnel_manager_pdu:
            return await tunnel_manager_pdu[pdu_type](endpoint, pdu)
        else:
            return self.packet_error(tunnel, "Unhandled packet PDU type %s" % pdu_type, data)

    def error_received(self, exc):
        """Called when a send or receive operation raises an OSError.
        (Other than BlockingIOError or InterruptedError.)
        """
        pass
