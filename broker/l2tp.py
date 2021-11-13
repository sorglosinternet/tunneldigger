import logging
import traceback

import genetlink
import netlink

LOG = logging.getLogger("tunneldigger.l2tp")

# L2TP generic netlink
L2TP_GENL_NAME = b"l2tp"
L2TP_GENL_VERSION = 0x1

# L2TP netlink commands
L2TP_CMD_TUNNEL_CREATE = 1
L2TP_CMD_TUNNEL_DELETE = 2
L2TP_CMD_TUNNEL_GET = 4
L2TP_CMD_SESSION_CREATE = 5
L2TP_CMD_SESSION_DELETE = 6
L2TP_CMD_SESSION_MODIFY = 7
L2TP_CMD_SESSION_GET = 8

# L2TP netlink command attributes
L2TP_ATTR_NONE = 0
L2TP_ATTR_PW_TYPE = 1
L2TP_ATTR_ENCAP_TYPE = 2
L2TP_ATTR_PROTO_VERSION = 7
L2TP_ATTR_IFNAME = 8
L2TP_ATTR_CONN_ID = 9
L2TP_ATTR_PEER_CONN_ID = 10
L2TP_ATTR_SESSION_ID = 11
L2TP_ATTR_PEER_SESSION_ID = 12
L2TP_ATTR_FD = 23
L2TP_ATTR_MTU = 28

# L2TP encapsulation types
L2TP_ENCAPTYPE_UDP = 0

# L2TP pseudowire types
L2TP_PWTYPE_ETH = 0x0005


class NetlinkError(Exception):
    pass


class L2TPSupportUnavailable(NetlinkError):
    pass


class L2TPTunnelExists(NetlinkError):
    pass


class NetlinkInterface(object):
    """
    NETLINK interface to L2TP kernel module.
    """

    def __init__(self):
        """
        Class constructor.
        """
        # Establish a connection to the kernel via the NETLINK socket
        self.connection = netlink.Connection(netlink.NETLINK_GENERIC)
        self._family_id = None

    async def _create_message(self, command, attributes, flags=netlink.NLM_F_REQUEST | netlink.NLM_F_ACK):
        return genetlink.GeNlMessage(await self.family_id, cmd=command, version=L2TP_GENL_VERSION,
                                     attrs=attributes, flags=flags)

    @property
    async def family_id(self):
        if self._family_id is not None:
            return self._family_id

        controller = genetlink.Controller(self.connection)
        try:
            self._family_id = await controller.get_family_id(L2TP_GENL_NAME)
        except OSError:
            raise L2TPSupportUnavailable

        return self._family_id

    async def tunnel_create(self, tunnel_id, peer_tunnel_id, socket):
        """
        Creates a new L2TP tunnel.

        :param tunnel_id: Local tunnel identifier
        :param peer_tunnel_id: Remote peer tunnel identifier
        :param socket: UDP socket file descriptor
        """
        msg = await self._create_message(L2TP_CMD_TUNNEL_CREATE, [
            netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
            netlink.U32Attr(L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id),
            netlink.U8Attr(L2TP_ATTR_PROTO_VERSION, 3),
            netlink.U16Attr(L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP),
            netlink.U32Attr(L2TP_ATTR_FD, socket),
        ])
        await msg.send(self.connection)

        try:
            _reply = await self.connection.recv()
        except OSError as e:
            if e.errno == 17:
                # This tunnel identifier is already in use; make sure to remove it from
                # our pool of assignable tunnel identifiers
                raise L2TPTunnelExists

            raise NetlinkError

    async def tunnel_delete(self, tunnel_id):
        """
        Deletes an existing tunnel.

        :param tunnel_id: Local tunnel identifier
        """
        msg = await self._create_message(L2TP_CMD_TUNNEL_DELETE, [
            netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
        ])
        await msg.send(self.connection)

        try:
            _reply = await self.connection.recv()
        except OSError:
            LOG.debug(traceback.format_exc())
            LOG.warning("Unable to remove tunnel %d!" % tunnel_id)

    async def tunnel_list(self):
        """
        Returns a list of tunnel identifiers.
        """
        tunnels = []
        msg = await self._create_message(L2TP_CMD_TUNNEL_GET, [],
                                         flags=netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP | netlink.NLM_F_ACK)
        await msg.send(self.connection)

        for tunnel in await genetlink.GeNlMessage.recv(self.connection, multiple=True):
            tunnels.append(tunnel.attrs[L2TP_ATTR_CONN_ID].u32())

        return tunnels

    async def session_create(self, tunnel_id, session_id, peer_session_id, name):
        """
        Creates a new ethernet session over the tunnel.

        :param tunnel_id: Local tunnel identifier
        :param session_id: Local session identifier
        :param peer_session_id: Remote peer session identifier
        :param name: Interface name
        """
        msg = await self._create_message(L2TP_CMD_SESSION_CREATE, [
            netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
            netlink.U32Attr(L2TP_ATTR_SESSION_ID, session_id),
            netlink.U32Attr(L2TP_ATTR_PEER_SESSION_ID, peer_session_id),
            netlink.U16Attr(L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH),
            # TODO cookies
            netlink.NulStrAttr(L2TP_ATTR_IFNAME, bytes(name, 'utf-8')),
        ])
        await msg.send(self.connection)

        try:
            # TODO: parse return of session create
            _reply = await self.connection.recv()
        except OSError:
            raise NetlinkError

    async def session_delete(self, tunnel_id, session_id):
        """
        Deletes an existing session.

        :param tunnel_id: Local tunnel identifier
        :param session_id: Local session identifier
        """
        msg = await self._create_message(L2TP_CMD_SESSION_DELETE, [
            netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
            netlink.U32Attr(L2TP_ATTR_SESSION_ID, session_id),
        ])
        await msg.send(self.connection)

        try:
            # TODO: parse return of session delete
            _reply = await self.connection.recv()
        except OSError:
            LOG.debug(traceback.format_exc())
            LOG.warning("Unable to remove tunnel %d session %d!" % (tunnel_id, session_id))

    async def session_modify(self, tunnel_id, session_id, mtu):
        """
        Modifies an existing session.

        :param mtu: The maximum transmit unit
        :param tunnel_id: Local tunnel identifier
        :param session_id: Local session identifier
        """
        msg = await self._create_message(L2TP_CMD_SESSION_MODIFY, [
            netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
            netlink.U32Attr(L2TP_ATTR_SESSION_ID, session_id),
            netlink.U16Attr(L2TP_ATTR_MTU, mtu),
        ])
        await msg.send(self.connection)

        try:
            _reply = await self.connection.recv()
        except OSError:
            LOG.debug(traceback.format_exc())
            LOG.warning("Unable to modify tunnel %d session %d!" % (tunnel_id, session_id))

    async def session_list(self):
        """
        Returns a list of session identifiers for each tunnel.
        """
        sessions = []
        msg = await self._create_message(L2TP_CMD_SESSION_GET, [],
                                         flags=netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP | netlink.NLM_F_ACK)
        await msg.send(self.connection)

        for session in await genetlink.GeNlMessage.recv(self.connection, multiple=True):
            sessions.append(
                (session.attrs[L2TP_ATTR_CONN_ID].u32(), session.attrs[L2TP_ATTR_SESSION_ID].u32())
            )

        return sessions
