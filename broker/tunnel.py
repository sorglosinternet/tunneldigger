import asyncio
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
    def __init__(self, broker, bind, remote, uuid, tunnel_id, remote_tunnel_id, pmtu_fixed, cookie,
                 client_features=0):
        """
        Construct a tunnel.

        :param broker: Broker instance that received the initial request
        :param bind: Destination broker address (host, port) tuple
        :param remote: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param tunnel_id: Locally assigned tunnel identifier
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        """
        self.broker = broker
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
        self.transport = self.protocol = None
        self.session_id = self.id if self.client_features & FEATURE_UNIQUE_SESSION_ID else 1
        self.remote_session_id = self.remote_tunnel_id
        self.session_name = "l2tp%d%d" % (self.session_id, self.remote_session_id)
        self.cookie = cookie
        self.socket = None

        self.pmtu = 1446
        self.peer_pmtu = None
        self.probed_pmtu = 0
        self.tunnel_mtu = 1446
        self.session = None
        self.pmtu_fixed = pmtu_fixed

    def __repr__(self):
        return "<Tunnel %d/%d>" % (self.id, self.remote_tunnel_id)

    def _next_keepalive_sequence_number(self):
        self.last_keepalive_sequence_number += 1
        if self.last_keepalive_sequence_number >= (2 ** 32):
            self.last_keepalive_sequence_number = 0
        return self.last_keepalive_sequence_number

    def setup(self):
        """
        Setup the tunnel and netfilter rules.
        """
        asyncio.create_task(self.setup_tunnel())

    async def _keep_alive_do(self):
        """
        Periodically transmits keepalives over the tunnel and checks
        if the tunnel has timed out due to inactivity.
        The sequence number is needed because some ISP (usually cable or mobile operators)
        do some "optimisation" and drop udp packets containing the same content.
        """
        while True:
            self.protocol.tx_keepalive(self.remote, self._next_keepalive_sequence_number())

            # Check if we are still alive or not; if not, kill the tunnel
            timeout_interval = self.broker.config.getint("broker", "tunnel_timeout")
            if datetime.datetime.now() - self.last_alive > datetime.timedelta(seconds=timeout_interval):
                if self.broker.config.getboolean('log', 'log_ip_addresses'):
                    LOG.warning("Session with tunnel %d to %s:%d timed out." % (self.id, self.remote[0],
                                                                                self.remote[1]))
                else:
                    LOG.warning("Session with tunnel %d timed out." % self.id)

                asyncio.create_task(self.broker.close_tunnel(self,
                    PDUDirection.ERROR_REASON_FROM_SERVER.value & PDUError.ERROR_REASON_TIMEOUT.value))
                return

            await asyncio.sleep(60.0)

    async def _pmtu_probe_do(self):
        """
        Periodically probes PMTU.
        """
        if self.pmtu_fixed:
            return

        probe_interval = 15
        while True:
            await asyncio.sleep(probe_interval)

            # Reset measured PMTU
            self.probed_pmtu = 0
            self.num_pmtu_probes = 0
            self.num_pmtu_replies = 0

            # Transmit PMTU probes of different sizes multiple times
            for _ in range(4):
                for size in [1334, 1400, 1450, 1476, 1492, 1500]:
                    try:
                        self.protocol.tx_pmtu(self.remote, size)
                        self.num_pmtu_probes += 1
                    except Exception:
                        pass
                await asyncio.sleep(1)

            # Collect all acknowledgements
            if self.num_pmtu_probes != self.num_pmtu_replies:
                await asyncio.sleep(3)

            detected_pmtu = max(self.probed_pmtu - L2TP_TUN_OVERHEAD, 1280)
            if not self.probed_pmtu or not self.num_pmtu_replies:
                LOG.warning("Got no replies to any PMTU probes for tunnel %d." % self.id)
                continue
            elif detected_pmtu > 0 and detected_pmtu != self.pmtu:
                self.pmtu = detected_pmtu
                asyncio.create_task(self._update_mtu())

            # Notify the client of the detected PMTU
            self.protocol.tx_pmtunotify(self.remote, self.pmtu)

            # Increase probe interval until it reaches 10 minutes
            probe_interval = min(600, probe_interval * 2)

    async def _update_mtu(self):
        detected_pmtu = max(1280, min(self.pmtu, self.peer_pmtu or 1446))
        if detected_pmtu == self.tunnel_mtu:
            return

        await self.broker.session_set_mtu(self, detected_pmtu)

        # Invoke MTU change hook for each session
        await self.broker.hook('session.mtu-changed', self.id, self.session_id, self.session_name,
                               self.tunnel_mtu,
                               detected_pmtu, self.uuid)

        LOG.debug("Detected PMTU of %d for tunnel %d." % (detected_pmtu, self.id))
        self.tunnel_mtu = detected_pmtu

    def rx_error(self, pdu):
        if pdu.error:
            LOG.warning(
                "Error message received from client, tearing down tunnel %d. Reason %d" % (self.id, pdu.error))
        else:
            LOG.warning("Error message received from client, tearing down tunnel %d." % self.id)
        asyncio.create_task(self.broker.close_tunnel(self,
                                                     PDUDirection.ERROR_REASON_FROM_SERVER.value & PDUError.ERROR_REASON_OTHER_REQUEST.value))

    def rx_pmtu(self, data):
        if self.pmtu_fixed:
            return

        # Reply with ACK packet
        self.protocol.tx_pmtuack(self.remote, len(data))
        # self.handler.send_message(self.socket, CONTROL_TYPE_PMTUD_ACK,
        #   construct.Int16ub.build(len(data)))

    def rx_pmtuack(self, pdu):
        # Decode ACK packet and extract size
        psize = pdu.pmtu + IPV4_HDR_OVERHEAD
        self.num_pmtu_replies += 1

        if psize > self.probed_pmtu:
            self.probed_pmtu = psize

    def rx_pmtunotify(self, pdu):
        if not self.broker.config.getboolean("broker", "pmtu_discovery"):
            return
        # Decode MTU notification packet
        if self.peer_pmtu != pdu.pmtu:
            self.peer_pmtu = pdu.pmtu
            asyncio.create_task(self._update_mtu())

        # TODO: reliable ACK on type reliable

    def rx_limit(self, limit_type, pdu):
        # Client requests limit configuration
        if not self.limits.configure(limit_type, pdu):
            LOG.warning("Unknown type of limit (%d) requested on tunnel %d." % (pdu.type, self.id))
            return

    def rx_keepalive(self, _pdu):
        self.keep_alive()

    async def close(self, kill=True, reason=PDUError.ERROR_REASON_UNDEFINED.value):
        """
        Close the tunnel and remove all mappings.
        """
        for task in [self.keep_alive_do, self.pmtu_probe_do]:
            if task:
                task.cancel()

        # Invoke any pre-down hooks
        await self.broker.hook('session.pre-down', self.id, self.session_id, self.session_name, self.pmtu,
                               self.remote[0],
                               self.remote[1], self.remote[1], self.uuid)

        await self.broker.netlink.session_delete(self.id, self.session_id)

        # Invoke any down hooks
        await self.broker.hook('session.down', self.id, self.session_id, self.session_name, self.pmtu, self.remote[0],
                               self.remote[1], self.remote[1], self.uuid)

        # Transmit error message so the other end can tear down the tunnel
        # immediately instead of waiting for keepalive timeout
        self.protocol.tx_error(self.remote, reason)

    async def setup_tunnel(self):
        """
        Sets up the L2TPv3 kernel tunnel for data transfer.
        """
        try:
            self.socket = get_socket(self.bind)
            self.socket.connect(self.remote)
            self.socket.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)
            self.transport, self.protocol = await self.loop.create_datagram_endpoint(
                lambda: TunneldiggerProtocol(self.broker, self),
                sock=self.socket)
        except socket.error:
            raise TunnelSetupFailed

        # Setup some default values for PMTU
        self.pmtu = 1446
        self.peer_pmtu = None
        self.probed_pmtu = 0
        self.tunnel_mtu = 1446

        # Make the socket an encapsulation socket by asking the kernel to do so
        try:
            await self.broker.netlink.tunnel_create(self.id, self.remote_tunnel_id, self.socket.fileno())
            await self.broker.netlink.session_create(self.id, self.session_id, self.remote_session_id,
                                                     self.session_name)
        except L2TPTunnelExists as exc:
            self.socket.close()
            self.broker.tunnel_exception(self, exc)
        except NetlinkError as exc:
            self.socket.close()
            self.broker.tunnel_exception(self, exc)

        # Spawn periodic keepalive transmitter and PMTUD
        self.keep_alive_do = asyncio.create_task(self._keep_alive_do())
        self.pmtu_probe_do = asyncio.create_task(self._pmtu_probe_do())

    def call_session_up_hooks(self):
        """
        Invokes any registered session establishment hooks for all sessions. This
        method must be called AFTER the tunnel has been established (after a
        confirmation packet has been transmitted from the broker to the client),
        otherwise port translation will not work and the tunnel will be dead.
        """
        asyncio.create_task(self.broker.hook('session.up', self.id, self.session_id, self.session_name, self.pmtu,
                                             self.remote[0], self.remote[1], self.remote[1], self.uuid))

    def keep_alive(self):
        """
        Marks this tunnel as alive at this moment.
        """
        self.last_alive = datetime.datetime.now()


class TunnelSetupFailed(Exception):
    pass
