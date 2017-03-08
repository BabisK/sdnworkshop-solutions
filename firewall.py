from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

IDLE_TIMOUT = 5
HARD_TIMEOUT = 15

def launch (blacklist=None, whitelist=None):
    """
    Launch is the entry point of the module, much like __main__
    """
    global BLACKLIST, WHITELIST
    if blacklist:
        BLACKLIST = blacklist.split(",")
    else:
        BLACKLIST = []
    if whitelist:
        WHITELIST = whitelist.split(",")
    else:
        WHITELIST = []

    # Register the switch_component to the system
    core.registerNew(SwitchComponent)

class SwitchComponent(object):
    '''
    The switch component is the handler of opendlow events for our 
    application
    '''
    def __init__(self):
        log.info("Starting SwitchComponent")
        
        # Make the switch component a listener to openflow events
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp(self, event):
        log.info("Creating switch device on %s" % (event.connection,))
        
        # Create a new Hub on the device having this connection
        Switch(event.connection)

class Switch(object):
    '''
    The switch class is instantiated once for each openflow device
    that connects to the switch component. The switch class tranforms
    the said device to an ethernet learning switch
    '''
    
    # The connection to device object
    connection = None
    
    def __init__(self, connection):
        '''
        Create the Switch instance
        '''
        # Store the connection object in the instance
        self.connection = connection
        
        # The MAC table linking MAC addresses with ports
        self.mac_table = {}
        
        # Register to the connection to listen events from the device
        # and pass them to the instance (self)
        connection.addListeners(self)
    
    def _handle_PacketIn (self, event):
        '''
        Callback function that receives packet_in events and responds
        to them. Packet in events are sent from the device and carry a
        data packet that the device does not know what to do with
        '''
        
        # Extract the data packet from the packet in event
        data = event.parsed

        firewall_rule_updated = self.handle_firewall(event)
        if firewall_rule_updated:
            return
        
        # Update the MAC table. The MAC address that is the source of
        # the frame is served from the port where this packet originated
        # We should store (or update) this relation
        self.mac_table[data.src] = event.port
        
        # We extract the destination MAC address from the data
        dst = data.dst
        
        if dst.is_multicast:
            # If the destination MAC is a multicast address, send the
            # frame out of all ports, like a hub
            log.info("Received multicast from %s" % (self.connection,))
            
            # Create a new flow_mod message
            msg = of.ofp_flow_mod()
            
            # Set the hard and idle timeouts to sane values
            msg.idle_timeout = IDLE_TIMOUT
            msg.hard_timeout = HARD_TIMEOUT
            
            # Match the destination mac address that triggered this packet_in event
            msg.match = of.ofp_match(dl_dst=dst)
            
            # Flood the packet to all ports (but the incoming)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            
            # Set the buffer of the message that triggered the packet in event
            # This way that message will be treated by the new flow and will
            # not be lost
            msg.buffer_id = event.ofp.buffer_id
            
            # Send the message to the switch
            self.connection.send(msg)
        else:       
            if dst in self.mac_table:
                # If the destination MAC address exists in the MAC table
                # we will send the packet out from the port the MAC
                # table has stored, unless it is the same as the
                # incoming port
                
                if event.port == self.mac_table[dst]:
                    # If the source port is the same as the destination
                    # port do nothing (efectively drop the packet)
                    pass
                else:
                    # If the source port is different than the destinationport
                    # create a new flow matching the port-mac_src-mac_dst and
                    # push it to the device
                    log.info("Received unicast from %s with known destination %s" % (self.connection, dst))
                    
                    # Create a new flow_mod message
                    msg = of.ofp_flow_mod()
                    
                    # Match the destination MAC address with the one received in the message carried by the packet_in
                    msg.match = of.ofp_match(dl_dst=data.dst)
                    
                    # Set timeouts to sane values
                    msg.idle_timeout = IDLE_TIMOUT
                    msg.hard_timeout = HARD_TIMEOUT
                    
                    # Send this message to the port indicated by the MAC table
                    msg.actions.append(of.ofp_action_output(port = self.mac_table[dst]))
                    
                    # Set the buffer of the message that triggered the packet in event
                    # This way that message will be treated by the new flow and will
                    # not be lost
                    msg.buffer_id = event.ofp.buffer_id
                    
                    # Send the message to the switch
                    self.connection.send(msg)
            else:
                # If the destination MAC address is not in the MAC table
                # Flood the message to all ports excpet the incoming one
                # Hopefully the destination will answer and eventually his
                # port will become known
                log.info("Received unicast from %s with uknown destination %s" % (self.connection, dst))
                
                # Create a new packet_out message
                msg = of.ofp_packet_out()
                
                # Indicate the port this packet came from
                msg.in_port = event.port
                
                # Set the action to flood the packet
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                
                # Set the data to flood
                msg.data = event.ofp
                
                # Send the message to the switch
                self.connection.send(msg)

    def handle_firewall(self, event):
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
            if decapsulated_packet.dstip in BLACKLIST and \
               decapsulated_packet.srcip not in WHITELIST:
                log.info("Blocking event for packet %s", decapsulated_packet.dstip)

                msg = of.ofp_flow_mod()
                msg.priority = of.OFPP_MAX
                msg.match.dl_type = 0x800
                msg.match.nw_dst = str(decapsulated_packet.dstip)
                msg.match.nw_src = str(decapsulated_packet.srcip)
                # no actions = drop

                log.debug("Sending openflow message %s", msg)
                event.connection.send(msg)
                return True
