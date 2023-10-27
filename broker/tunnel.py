import asyncio
import time

import asyncio_dgram
import datetime
import logging
import socket

from l2tp import L2TPTunnelExists, NetlinkError
from limits import Limits
from protocol import PDUDirection, PDUError, L2TP_TUN_OVERHEAD, IPV4_HDR_OVERHEAD, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE, \
    FEATURE_UNIQUE_SESSION_ID, TunneldiggerProtocol

LOG = logging.getLogger("tunneldigger.tunnel")

def get_socket(bind):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
    sock.bind(bind)
    return sock

class Tunnel(object):
    def __init__(self, manager, bind, remote, uuid, tunnel_id, remote_tunnel_id, pmtu_fixed, cookie,
                 client_features=0):
        """
        Construct a tunnel.

        :param manager: Broker instance that received the initial request
        :param bind: Destination broker address (host, port) tuple
        :param remote: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param tunnel_id: Locally assigned tunnel identifier
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        """
        self.manager = manager
        self.limits = Limits(self)
        self.next_session_id = 1
        self.id = tunnel_id
        self.last_alive = datetime.datetime.now()
        self.last_keepalive_sequence_number = 0
        self.keep_alive_do = None
        self.pmtu_probe_do = None
        self.bind = bind
        self.remote = remote
        self.loop = asyncio.get_running_loop()
        self.uuid = uuid
        self.remote_tunnel_id = remote_tunnel_id
        self.client_features = client_features
        self.protocol = TunneldiggerProtocol(self.manager, self)
        self.session_id = self.id if self.client_features & FEATURE_UNIQUE_SESSION_ID else 1
        self.remote_session_id = self.remote_tunnel_id
        self.session_name = "l2tp%d%d" % (self.session_id, self.remote_session_id)
        self.cookie = cookie
        # low level unix socket
        self.llsocket = None
        # high level asyncudp socket
        self.socket = None

        self.pmtu = 1446
        self.peer_pmtu = None
        self.probed_pmtu = 0
        self.tunnel_mtu = 1446
        self.session = None
        self.pmtu_fixed = pmtu_fixed
        self.closing = False
        self.uptime = time.monotonic()
        self.uptime_dt = datetime.datetime.now()
        self.downtime = None
        self.downtime_dt = None

    def __repr__(self):
        return "<Tunnel %d/%d>" % (self.id, self.remote_tunnel_id)

    def _next_keepalive_sequence_number(self):
        self.last_keepalive_sequence_number += 1
        if self.last_keepalive_sequence_number >= (2 ** 32):
            self.last_keepalive_sequence_number = 0
        return self.last_keepalive_sequence_number

    def time_since_up(self):
        if self.downtime:
            return self.downtime - self.uptime
        else:
            return time.monotonic() - self.uptime

    async def _keep_alive_do(self):
        """
        Periodically transmits keepalives over the tunnel and checks
        if the tunnel has timed out due to inactivity.
        The sequence number is needed because some ISP (usually cable or mobile operators)
        do some "optimisation" and drop udp packets containing the same content.
        """
        while not self.closing:
            await self.protocol.tx_keepalive(self.remote, self._next_keepalive_sequence_number())

            # Check if we are still alive or not; if not, kill the tunnel
            timeout_interval = self.manager.config.getint("broker", "tunnel_timeout")
            if datetime.datetime.now() - self.last_alive > datetime.timedelta(seconds=timeout_interval):
                if self.manager.config.getboolean('log', 'log_ip_addresses'):
                    LOG.warning("Session with tunnel %d to %s:%d timed out. (uptime: %d)" % (self.id, self.remote[0],
                                                                                self.remote[1], self.time_since_up()))
                else:
                    LOG.warning("Session with tunnel %d timed out (uptime: %d)." % (self.id, self.time_since_up()))

                if not self.closing:
                    asyncio.create_task(self.manager.close_tunnel(self, PDUDirection.ERROR_REASON_FROM_SERVER.value & PDUError.ERROR_REASON_TIMEOUT.value))
                return

            await asyncio.sleep(60.0)

    async def _pmtu_probe_do(self):
        """
        Periodically probes PMTU.
        """
        if self.pmtu_fixed:
            return

        probe_interval = 15
        while not self.closing:
            await asyncio.sleep(probe_interval)

            # Reset measured PMTU
            self.probed_pmtu = 0
            self.num_pmtu_probes = 0
            self.num_pmtu_replies = 0

            # Transmit PMTU probes of different sizes multiple times
            for _ in range(4):
                for size in [1334, 1400, 1450, 1476, 1492, 1500]:
                    try:
                        await self.protocol.tx_pmtu(self.remote, size)
                        self.num_pmtu_probes += 1
                    except asyncio.TimeoutError:
                        raise
                    except OSError as err:
                        # ignore Message too long exceptions
                        if err.errno == 90:
                            break
                        LOG.exception("Got unhandled PMTU OSError exception")
                    except Exception:
                        LOG.exception("Got unhandled PMTU exception")
                await asyncio.sleep(1)

            # Collect all acknowledgements
            if self.num_pmtu_probes != self.num_pmtu_replies:
                await asyncio.sleep(3)

            detected_pmtu = max(self.probed_pmtu - L2TP_TUN_OVERHEAD, 1280)
            if not self.probed_pmtu or not self.num_pmtu_replies:
                LOG.warning("Got no replies to any PMTU probes for tunnel %d/%s." % (self.id, self.uuid))
                continue
            elif detected_pmtu > 0 and detected_pmtu != self.pmtu:
                self.pmtu = detected_pmtu
                await self._update_mtu()

            # Notify the client of the detected PMTU
            await self.protocol.tx_pmtunotify(self.remote, self.pmtu)

            # Increase probe interval until it reaches 10 minutes
            probe_interval = min(600, probe_interval * 2)

    async def _update_mtu(self):
        detected_pmtu = max(1280, min(self.pmtu, self.peer_pmtu or 1446))
        if detected_pmtu == self.tunnel_mtu:
            return

        await self.manager.session_set_mtu(self, detected_pmtu)

        # Invoke MTU change hook for each session
        await self.manager.hook('session.mtu-changed', self.id, self.session_id, self.session_name,
                                self.tunnel_mtu,
                                detected_pmtu, self.uuid)

        LOG.debug("Detected PMTU of %d for tunnel %d." % (detected_pmtu, self.id))
        self.tunnel_mtu = detected_pmtu

    async def rx_error(self, pdu):
        if pdu.error:
            if pdu.error & PDUError.ERROR_REASON_SHUTDOWN.value:
                who = "server" if pdu.error & 0x0f == PDUDirection.ERROR_REASON_FROM_SERVER.value else "client"
                LOG.info("%s requested to normal shutdown tunnel %d", who, self.id)
            else:
                LOG.warning(
                    "Error message received from client, tearing down tunnel %d. Reason %d" % (self.id, pdu.error))
        else:
            LOG.warning("Error message received from client, tearing down tunnel %d." % self.id)
        await self.manager.close_tunnel(self, PDUDirection.ERROR_REASON_FROM_SERVER.value & PDUError.ERROR_REASON_OTHER_REQUEST.value)

    async def rx_pmtu(self, data):
        if self.pmtu_fixed:
            return

        # Reply with ACK packet
        await self.protocol.tx_pmtuack(self.remote, len(data))
        # self.handler.send_message(self.socket, CONTROL_TYPE_PMTUD_ACK,
        #   construct.Int16ub.build(len(data)))

    async def rx_pmtuack(self, pdu):
        # Decode ACK packet and extract size
        psize = pdu.pmtu + IPV4_HDR_OVERHEAD
        self.num_pmtu_replies += 1

        if psize > self.probed_pmtu:
            self.probed_pmtu = psize

    async def rx_pmtunotify(self, pdu):
        if not self.manager.config.getboolean("broker", "pmtu_discovery"):
            return
        # Decode MTU notification packet
        if self.peer_pmtu != pdu.pmtu:
            self.peer_pmtu = pdu.pmtu
            await self._update_mtu()

        # TODO: reliable ACK on type reliable

    async def rx_limit(self, limit_pdu, limit_config_pdu):
        # Client requests limit configuration
        # TODO: configure as async?
        if not self.limits.configure(limit_pdu.type, limit_config_pdu):
            LOG.warning("Unknown type of limit (%d) requested on tunnel %d." % (limit_pdu.type, self.id))
        await self.protocol.tx_relack(self.remote, limit_pdu.sequence)

    async def rx_keepalive(self, _pdu):
        self.keep_alive()

    async def close(self, reason=PDUError.ERROR_REASON_UNDEFINED.value, send_tx_error=True):
        """
        Close the tunnel and remove all mappings.
        """
        if self.closing:
            return
        self.closing = True
        self.downtime = time.monotonic()
        self.downtime_dt = datetime.datetime.now()
        for task in [self.keep_alive_do, self.pmtu_probe_do]:
            if task:
                task.cancel()

        # Invoke any pre-down hooks
        await self.manager.hook('session.pre-down', self.id, self.session_id, self.session_name, self.pmtu,
                                self.remote[0],
                                self.remote[1], self.remote[1], self.uuid)

        await self.manager.netlink.session_delete(self.id, self.session_id)
        await self.manager.netlink.tunnel_delete(self.id)

        # Invoke any down hooks
        await self.manager.hook('session.down', self.id, self.session_id, self.session_name, self.pmtu, self.remote[0],
                                self.remote[1], self.remote[1], self.uuid)

        # Transmit error message so the other end can tear down the tunnel
        # immediately instead of waiting for keepalive timeout
        if send_tx_error:
            await self.manager.protocol.tx_error(self.remote, reason)
        self.socket.close()


    async def setup_tunnel(self):
        """
        Sets up the L2TPv3 kernel tunnel for data transfer.
        """
        try:
            self.llsocket = get_socket(self.bind)
            self.llsocket.connect(self.remote)
            self.llsocket.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)
            self.socket = await asyncio_dgram.from_socket(sock=self.llsocket)
            self.protocol.socket = self.socket
            self.sock_do = asyncio.create_task(self.protocol.sock_loop())

        except socket.error:
            raise TunnelSetupFailed

        # Setup some default values for PMTU
        self.pmtu = 1446
        self.peer_pmtu = None
        self.probed_pmtu = 0
        self.tunnel_mtu = 1446

        # Make the socket an encapsulation socket by asking the kernel to do so
        try:
            await self.manager.netlink.tunnel_create(self.id, self.remote_tunnel_id, self.llsocket.fileno())
            await self.manager.netlink.session_create(self.id, self.session_id, self.remote_session_id,
                                                      self.session_name)
        except L2TPTunnelExists as exc:
            self.llsocket.close()
            self.manager.tunnel_exception(self, exc)
        except NetlinkError as exc:
            self.llsocket.close()
            self.manager.tunnel_exception(self, exc)

        # Spawn periodic keepalive transmitter and PMTUD
        self.keep_alive_do = asyncio.create_task(self._keep_alive_do())
        self.pmtu_probe_do = asyncio.create_task(self._pmtu_probe_do())

    async def call_session_up_hooks(self):
        """
        Invokes any registered session establishment hooks for all sessions. This
        method must be called AFTER the tunnel has been established (after a
        confirmation packet has been transmitted from the broker to the client),
        otherwise port translation will not work and the tunnel will be dead.
        """
        await self.manager.hook('session.up', self.id, self.session_id, self.session_name, self.pmtu,
                                              self.remote[0], self.remote[1], self.remote[1], self.uuid)

    async def socket_error(self, exc):
        """
        Called by the protocol to handle socket errors

        @param error_no: An os errno if available
        @type error_no: int
        @param exc: The exception to throw
        @type exc: Exception
        @return: True if the sock_loop should be continued
        @rtype: bool
        """
        if isinstance(exc, OSError):
            error_no = exc.errno

            if error_no == errno.EMSGSIZE:
                # ignore Message too long exception
                return True
            elif error_no == errno.ECONNREFUSED:
                asyncio.get_running_loop().call_soon(asyncio.create_task(self.close(send_tx_error=False)))
            elif error_no is not None:
                LOG.exception("Unknown OSError, closing tunnel")
                asyncio.get_running_loop().call_soon(asyncio.create_task(self.close(PDUError.ERROR_REASON_FAILURE)))
        elif isinstance(exc, asyncio_dgram.aio.TransportClosed):
            asyncio.get_running_loop().call_soon(asyncio.create_task(self.close()))
        else:
            LOG.exception("Socket loop received unknown exception. Closing tunnel")
            asyncio.get_running_loop().call_soon(asyncio.create_task(self.close()))

        return False

    def keep_alive(self):
        """
        Marks this tunnel as alive at this moment.
        """
        self.last_alive = datetime.datetime.now()


class TunnelSetupFailed(Exception):
    pass
