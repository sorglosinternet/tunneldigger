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
import shlex

TC = '/sbin/tc'


class TrafficControlError(Exception):
    pass


class TrafficControl(object):
    def __init__(self, interface):
        """
        Class constructor.

        :param interface: Name of traffic controller interface
        """
        self.interface = interface

    async def tc(self, command: str, ignore_fails=False):
        """
        Executes a traffic control command.
        """
        cmds = [TC] + shlex.split(command)
        script_process = await asyncio.create_subprocess_exec(
            *cmds,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        exit_code = await script_process.wait()

        if exit_code != 0 and not ignore_fails:
            raise TrafficControlError

    async def reset(self):
        """
        Clears all existing traffic control rules.
        """
        await self.tc('qdisc del dev %s root handle 1: htb default 0' % self.interface, ignore_fails=True)
        await self.tc('qdisc add dev %s root handle 1: htb default 1' % self.interface)

    async def set_fixed_bandwidth(self, bandwidth):
        """
        Configures a fixed bandwidth class for this interface.

        :param bandwidth: Bandwidth limit in kbps
        """
        await self.reset()
        await self.tc('class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit' \
                      % (self.interface, bandwidth, bandwidth))
