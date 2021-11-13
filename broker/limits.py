import asyncio
import logging

from construct import ConstructError

import traffic_control
from protocol import LIMIT_TYPE_BANDWIDTH_DOWN

LOG = logging.getLogger("tunneldigger.limits")

class Limits(object):
    def __init__(self, tunnel):
        """
        Class constructor.

        :param tunnel: Tunnel instance
        """
        self.tunnel = tunnel

    def configure(self, limit_type, config_pdu):
        """
        Configures a specific limit.

        :param limit: Limit message type
        """
        if limit_type == LIMIT_TYPE_BANDWIDTH_DOWN:
            # Downstream (client-wise) limit setup
            try:
                bandwidth = config_pdu.bandwidth
            except ConstructError:
                LOG.warning("Invalid bandwidth limit requested on tunnel %d." % self.tunnel.id)
                return

            LOG.info("Setting bandwidth limit to %d kbps on tunnel %d." % (bandwidth, self.tunnel.id))

            # Setup bandwidth limit using Linux traffic shaping
            for session in self.tunnel.sessions.values():
                try:
                    tc = traffic_control.TrafficControl(session.name)
                    asyncio.get_running_loop().call_soon(tc.set_fixed_bandwidth, bandwidth)
                except traffic_control.TrafficControlError:
                    LOG.warning("Unable to configure traffic shaping rules for tunnel %d." % self.tunnel.id)

            return True
        else:
            return False