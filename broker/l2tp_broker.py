#!/usr/bin/python
#
# Broker for our custom L2TPv3 brokerage protocol.
#
# Copyright (C) 2012 by Jernej Kos <jernej@kos.mx>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import asyncio
import configparser
import fcntl
import logging.handlers
import os
import struct
import sys
import signal
import functools as ft

import asyncio_dgram
import repoze.lru

from l2tp import *
from protocol import PDUError, TunneldiggerProtocol, FEATURE_UNIQUE_SESSION_ID, SIOCSIFMTU
from tunnel import Tunnel, TunnelSetupFailed, get_socket

# Logger
logger = logging.getLogger("tunneldigger.broker")

# Check for required modules
required_modules = ['nfnetlink', 'l2tp_netlink', 'l2tp_core']


def check_for_modules():
    installed_modules = [line.strip().split(" ")[0] for line in open('/proc/modules')]
    for required_module in required_modules:
        if required_module not in installed_modules:
            return False

    return True


class TunnelManager(object):
    def __init__(self, config, close_future):
        """
        Class constructor.

        :param config: The configuration object
        """
        logger.info("Setting up the tunnel manager...")
        self.config = config
        self.max_tunnels = config.getint('broker', 'max_tunnels')
        self.netlink = NetlinkInterface()
        self.tunnels = {}
        self.cookies = repoze.lru.LRUCache(config.getint('broker', 'max_cookies'))
        self.secret = os.urandom(32)
        id_base = config.getint('broker', 'tunnel_id_base')
        # TODO: make tunnel_ids a set
        self.tunnel_ids = [x for x in range(id_base, id_base + self.max_tunnels + 1)]
        self.interface = config.get('broker', 'interface')
        self.address = config.get('broker', 'address')
        # TODO: add multiple port support again
        self.bind = (self.address, int(config.get('broker', 'port').split(',')[0]))

        self.closed = False
        self.loop = asyncio.get_running_loop()
        self.hooks = {}
        self.setup_hooks()
        self.protocol = TunneldiggerProtocol(self, None)
        self.close_future = close_future

        # Log some configuration variables
        logger.info("  Maximum number of tunnels: %d" % self.max_tunnels)
        logger.info("  Interface: %s" % self.interface)
        logger.info("  Binds: %s" % str(self.bind))

        asyncio.create_task(self.setup_tunnels())
        logger.info("Tunnel manager initialized.")

    def setup_hooks(self):
        """
        Sets up any registered hooks.
        """
        for hook, script in self.config.items('hooks'):
            self.hooks[hook] = script

    async def hook(self, name, *args):
        """
        Executes a given hook. All additional arguments are passed to the
        hook as script arguments.

        :param name: Hook name (like session.pre-up)
        """
        script = self.hooks.get(name, None)
        if not script:
            return

        # Execute the registered hook
        logger.debug("Executing hook '%s' via script '%s %s'." % (name, script, str([str(x) for x in args])))
        script_process = await asyncio.create_subprocess_exec(
                    script, *(str(x) for x in args),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL)
        await script_process.wait()

    async def cleanup_tunnels(self):
        """
        Cleans up any stale tunnels that exist and listen to the socket
        """
        for tunnel_id, session_id in await self.netlink.session_list():
            if tunnel_id in self.tunnel_ids:
                logger.warning("Removing existing tunnel %d session %d." % (tunnel_id, session_id))
                await self.netlink.session_delete(tunnel_id, session_id)

        for tunnel_id in await self.netlink.tunnel_list():
            if tunnel_id in self.tunnel_ids:
                logger.warning("Removing existing tunnel %d." % tunnel_id)
                await self.netlink.tunnel_delete(tunnel_id)

    async def setup_tunnels(self):
        await self.cleanup_tunnels()
        self.socket = await asyncio_dgram.from_socket(sock=get_socket(self.bind))
        self.protocol.socket = self.socket
        self.sock_do = asyncio.create_task(self.protocol.sock_loop())

    def tunnel_exception(self, tunnel: Tunnel, exc: Exception):
        """
        Called when a tunnel received an exception and need to be removed from the tunnel list

        :param tunnel:
        :param exc
        :return:
        """

        logger.warning("Tunnel %s received exception %s", tunnel, exc)
        logger.exception("")
        self.close_tunnel(tunnel, PDUError.ERROR_REASON_FAILURE)

    async def close(self):
        """
        Closes all tunnels and performs the necessary cleanup.
        """
        if self.closed:
            return

        self.closed = True
        logger.info("Closing the tunnel manager. Closing %d tunnels", len(self.tunnels))

        try:
            # Ensure that all tunnels get closed
            tunnels = (tunnel.close(reason=PDUError.ERROR_REASON_SHUTDOWN.value) for tunnel in self.tunnels.values())

            try:
                await asyncio.gather(*tunnels)
            except:
                logger.warning("Failed to close all tunnels!")
                logger.debug(traceback.format_exc())

            # Close any stale tunnels that might still be up
            id_base = self.config.getint('broker', 'tunnel_id_base')
            self.tunnel_ids = [x for x in range(id_base, id_base + self.max_tunnels + 1)]
            await self.cleanup_tunnels()
        finally:
            self.close_future.set_result(None)

    async def issue_cookie(self, endpoint, _pdu):
        """
        Issues a new cookie for the given endpoint.

        :param endpoint: Endpoint tuple
        :return: Some random cookie data (8 bytes)
        """
        cookie = self.cookies.get(endpoint)
        if cookie is not None:
            return cookie

        cookie = os.urandom(8)
        self.cookies.put(endpoint, cookie)
        await self.protocol.tx_cookie(endpoint, cookie)

    def calc_usage(self) -> int:
        return min(int(1.0 * (len(self.tunnels) / (self.max_tunnels * 1.0)) * 255), 255)

    async def usage(self, endpoint, _pdu):
        """
        send usage

        :param endpoint: Endpoint tuple
        :return: Usage information (1 byte)
          0 (broker is not used)..255 (broker is used to hard)
        """

        await self.protocol.tx_usage(endpoint, self.calc_usage())

    def verify_cookie(self, endpoint, cookie):
        """
        Verifies if the endpoint has generated a valid cookie.

        :param endpoint: Cookie
        """
        vcookie = self.cookies.get(endpoint)
        if not vcookie:
            return False

        return vcookie == cookie

    async def session_set_mtu(self, tunnel, mtu):
        """
        Sets MTU values for a specific device.

        :param tunnel: Tunnel instance
        :param session: Session instance
        :param mtu: Wanted MTU
        """

        # Ignore tunnel setup if the manager is closing.
        # ToDo: move this into tunnel
        if self.closed:
            return None, False

        try:
            ifreq = (bytes(tunnel.session_name, 'utf-8') + b'\0' * 16)[:16]
            data = struct.pack("16si", ifreq, mtu)
            fcntl.ioctl(tunnel.llsocket, SIOCSIFMTU, data)
        except IOError:
            logger.warning("Failed to set MTU for tunnel %d! Is the interface down?" % tunnel.id)

        await self.netlink.session_modify(tunnel.id, tunnel.session_id, mtu)

    async def close_tunnel(self, tunnel, reason=PDUError.ERROR_REASON_UNDEFINED.value):
        """
        Closes an existing tunnel.

        :param broker.tunnel.Tunnel tunnel: A tunnel instance that should be closed
        """
        if tunnel.remote not in self.tunnels:
            return

        if self.config.getboolean('log', 'log_ip_addresses'):
            logger.info("Closing tunnel %d to %s:%d." % (tunnel.id, tunnel.remote[0],
                                                         tunnel.remote[1]))
        else:
            logger.info("Closing tunnel %d." % tunnel.id)

        try:
            await tunnel.close(reason=reason)
        except:
            if self.config.getboolean('log', 'log_ip_addresses'):
                logger.error("Exception while closing tunnel %d to %s:%d!" % (tunnel.id,
                                                                              tunnel.remote[0], tunnel.remote[1]))
            else:
                logger.error("Exception while closing tunnel %d!" % tunnel.id)

            logger.debug(traceback.format_exc())

        try:
            del self.tunnels[tunnel.remote]
        except KeyError:
            pass
        self.tunnel_ids.append(tunnel.id)

    def get_tunnel(self, endpoint):
        if endpoint in self.tunnels:
            return self.tunnels[endpoint]
        return None

    async def unknown_tunnel(self, endpoint):
        """
        Received a pdu from an unknown tunnel.

        :param endpoint:
        :return:
        """
        # TODO: keep errors in a limited list to not answer every packet of an invalid tunnel
        await self.protocol.tx_error(endpoint, PDUError.ERROR_REASON_UNDEFINED.value)

    async def prepare(self, endpoint, pdu):
        """
        called when a prepare PDU has been received
        """
        # endpoint, uuid, cookie, tunnel_id):
        if self.verify_cookie(endpoint, pdu.cookie) == False:
            logger.warning("Received prepare pdu with invalid cookie for %s cookie %s", endpoint, pdu.cookie)
            return

        # Check for a cookie match
        if not self.verify_cookie(endpoint, pdu.cookie):
            return

        # First check if this tunnel has already been prepared
        tunnel, created = await self.setup_tunnel(self.bind, endpoint, pdu)
        if tunnel is None:
            await self.protocol.tx_error(endpoint, PDUError.ERROR_REASON_FAILURE.value)
            return
        await self.protocol.tx_tunnel(endpoint, tunnel.id, FEATURE_UNIQUE_SESSION_ID)

        # Invoke any session up hooks
        await tunnel.call_session_up_hooks()

    async def setup_tunnel(self, bind, remote, pdu):
        """
        Sets up a new tunnel or returns the data for an existing
        tunnel.

        :param bind: Tuple (ip, port) representing the endpoint
        :param remote: Tuple (ip, port) representing the endpoint

        :return: A tuple (tunnel, created) where tunnel is a Tunnel
          descriptor and created is a boolean flag indicating if a new
          tunnel has just been created; (None, False) if something went
          wrong
        """

        # Ignore tunnel setup if the manager is closing.
        if self.closed:
            return None, False

        if remote in self.tunnels:
            tunnel = self.tunnels[remote]

            # Check if UUID is a match and abort if it isn't; we should
            # not overwrite endpoints
            if tunnel.uuid != pdu.uuid:
                return None, False

            # Check if peer tunnel id is a match and abort if it isn't
            if tunnel.remote_tunnel_id != pdu.tunnel_id:
                return None, False

            # Update tunnel's liveness
            tunnel.keep_alive()
            return tunnel, False

        # Tunnel has not yet been created, create a new tunnel
        if len(self.tunnel_ids) == 0:
            logger.warning("Ignoring tunnel with id %s. Server is full." % pdu.uuid)
            return None, False
        local_tunnel_id = self.tunnel_ids.pop(0)
        remote_tunnel_id = 1
        if pdu.features is not None:
            if pdu.features & FEATURE_UNIQUE_SESSION_ID:
                remote_tunnel_id = pdu.tunnel_id

        client_features = pdu.features if pdu.features is not None else 0
        tunnel = Tunnel(self, bind, remote, pdu.uuid, local_tunnel_id,
                        remote_tunnel_id, False, pdu.cookie, client_features)
        self.tunnels[remote] = tunnel

        try:
            await tunnel.setup_tunnel()
        except IndexError:
            # No available tunnel indices, reject tunnel creation
            return None, False
        except L2TPTunnelExists:
            # Failed to setup a tunnel because the identifier already exists; abort,
            # but do not put the identifier back as tunnel with this identifier is
            # clearly not managed by us
            logger.warning("L2TP Tunnel with id %d already exists!" % tunnel.id)
            return None, False
        except TunnelSetupFailed:
            # Failed to setup a tunnel, abort now and reclaim the assigned id
            logger.exception("Failed to setup tunnel with id %d!" % tunnel.id)
            self.tunnel_ids.append(tunnel.id)
            return None, False

        if self.config.getboolean('log', 'log_ip_addresses'):
            logger.info("New tunnel (id=%d/%d uuid=%s) created with %s." % (tunnel.id, tunnel.remote_tunnel_id, tunnel.uuid, tunnel.remote))
        else:
            logger.info("New tunnel (id=%d/%d uuid=%s) created." % (tunnel.id, tunnel.remote_tunnel_id, tunnel.uuid))

        return tunnel, True

    def dump_broker(self, signal: str):
        logger.error("Received signal %s", signal)
        manager_state = f"""
Overview:
    Tunnels:                {len(self.tunnels)}
    Usage:                  {self.calc_usage()}
    Max:                    {self.max_tunnels}
"""
        logger.error(manager_state)
        for remote in self.tunnels:
            tunnel = self.tunnels[remote]
            output = f"""
Tunnel {tunnel.uuid} {tunnel.id}/{tunnel.remote_tunnel_id}
     remote uuid:           {tunnel.remote_tunnel_id}
     remote:                {tunnel.remote}
     pmtu:                  {tunnel.pmtu}
     session:               {tunnel.session_id} / {tunnel.remote_session_id}
     dev:                   {tunnel.session_name}
     cookie:                {tunnel.cookie}
     features:              {tunnel.client_features}
     last keep alive:       {tunnel.last_alive}
     last keep alive seq:   {tunnel.last_keepalive_sequence_number}
     uptime:                {tunnel.uptime}
     uptime_dt:             {tunnel.uptime_dt.isoformat()}
     downtime:              {tunnel.downtime}
     downtime_dt:           {tunnel.downtime_dt}
     keep job:              {tunnel.keep_alive_do}
     pmtu job:              {tunnel.pmtu_probe_do}
     closing:               {tunnel.closing}"""

            logger.error(output)


def setup_logging(config):
    filename = config.get("log", "filename")
    level = getattr(logging, config.get("log", "verbosity"))
    lineformat = '%(asctime)s %(levelname)-8s %(message)s'
    dateformat = '%a, %d %b %Y %H:%M:%S'

    handler = logging.handlers.WatchedFileHandler(filename)
    handler.setFormatter(logging.Formatter(lineformat, dateformat))

    logging.getLogger().setLevel(level)
    logging.getLogger().addHandler(handler)


async def main():
    try:
        # We must run as root
        if os.getuid() != 0:
            print("ERROR: Must be root.")
            sys.exit(1)

        # Parse configuration (first argument must be the location of the configuration
        # file)
        config = configparser.ConfigParser()
        try:
            config.read(sys.argv[1])
        except IOError:
            print("ERROR: Failed to open the specified configuration file '%s'!" % sys.argv[1])
            sys.exit(1)
        except IndexError:
            print("ERROR: First argument must be a configuration file path!")
            sys.exit(1)

        do_check_modules = True
        try:
            do_check_modules = config.getboolean("broker", "check_modules")
        except configparser.NoOptionError:
            pass

        if do_check_modules and not check_for_modules():
            print("ERROR: You must install the following kernel modules:")
            print(",".join(required_modules))
            sys.exit(1)

        setup_logging(config)
        # Setup the base control server.
        close_future = asyncio.Future()

        def shutdown_broker(signal: str):
            logger.error("Received signal %s", signal)
            print("Received signal %s" % signal)
            print("Shutting down ...")
            asyncio.ensure_future(manager.close())

        manager = TunnelManager(config, close_future)
        for signame in ('SIGINT', 'SIGTERM'):
            asyncio.get_running_loop().add_signal_handler(getattr(signal, signame), ft.partial(shutdown_broker, signame))
        asyncio.get_running_loop().add_signal_handler(getattr(signal, 'SIGUSR1'), ft.partial(manager.dump_broker, signame))

        await close_future

    except L2TPSupportUnavailable:
        logger.error("L2TP kernel support is not available.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
