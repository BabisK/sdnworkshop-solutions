# Copyright 2017 Intracom Telecom
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A simple IP firewall

"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

import pox.forwarding.learning
pox.forwarding.l3_learning.FLOW_IDLE_TIMEOUT = 1000  # monkeypatching for learning purposes


# Create a logger for this component
log = core.getLogger()


@poxutil.eval_args
def launch (blacklist=None, whitelist=None):
  """
  This is the entry point of the module that starts the Firewall

  Blacklist/Whitelist can be passed with the commandline args
  --blacklist=1.2.3.1,1.2.3.2 --whitelist=1.2.3.4,1.2.3.5
  and they are converted into python arrays like
  blacklist = ["1.2.3.1", "1.2.3.2"]
  whitelist = ["1.2.3.4", "1.2.3.4"]
  """
  if  blacklist:
    blacklist = blacklist.split(",")
  else:
    blacklist = []
  if whitelist:
    whitelist = whitelist.split(",")
  else:
    whitelist = []
  firewall = Firewall(blacklist, whitelist)
  core.openflow.addListenerByName("PacketIn", firewall._handle_PacketIn)

class Firewall(object):
  def __init__(self, blacklist, whitelist):
    self.blacklist = blacklist
    self.whitelist = whitelist

  def _handle_PacketIn(self, event):
    log.debug("Got a packet in event from switch %s", event.dpid)
    log.debug("Event packet type: %s", type(event.parsed))
    # The packet sent to the controller is an ethernet packet (L2)
    # This encapsulates the higher layer packet which we can get by calling next on
    # the L2 one.
    decapsulated_packet = event.parsed.next
    # There are many kinds of things this decapsulated packet could be eg
    # - any kind of L3 packet (IP, ICMP, RIP etc)
    # - a resolution packet  (ARP, NDP)
    # We need to handle only the ones we care about,
    # isinstance can used to do that.
    # The packet types defined for pox and documentation on them is
    # available in ~/pox/pox/lib/packet/
    # every filename is a packet class that can be used here
    # You can see in each packet's __init__ which fields it defines.
    if isinstance(decapsulated_packet, pkt.ipv4):
      log.debug("decapsulated packet dest ip: %s", decapsulated_packet.dstip)
      log.debug("decapsulated packet src ip: %s", decapsulated_packet.srcip)
      if decapsulated_packet.dstip in self.blacklist and \
        decapsulated_packet.srcip not in self.whitelist:
        log.debug("Blocking event for packet %s", decapsulated_packet.dstip)

        msg = of.ofp_flow_mod()
        msg.priority = of.OFPP_MAX
        msg.match.dl_type = 0x800
        msg.match.nw_dst = str(decapsulated_packet.dstip)
        msg.match.nw_src = str(decapsulated_packet.srcip)
        # no actions = drop

        log.debug("Sending openflow message %s", msg)
        event.connection.send(msg)
