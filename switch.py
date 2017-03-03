from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

IDLE_TIMOUT = 5
HARD_TIMEOUT = 15

def launch ():
  """
  Launch is the entry point of the module, much like __main__
  """

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
            
            # Create a new packet_out message
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
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
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match(in_port=event.port, dl_src=data.src, dl_dst=data.dst)
                    msg.idle_timeout = IDLE_TIMOUT
                    msg.hard_timeout = HARD_TIMEOUT
                    msg.actions.append(of.ofp_action_output(port = self.mac_table[dst]))
                    msg.data = event.ofp
                    self.connection.send(msg)
            else:
                # If the destination MAC address is not in the MAC table
                # Flood the message to all ports excpet the incoming one
                # Hopefully the destination will answer and eventually his
                # port will become known
                log.info("Received unicast from %s with uknown destination %s" % (self.connection, dst))
                msg = of.ofp_packet_out()
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                msg.data = event.ofp
                msg.in_port = event.port
                self.connection.send(msg)
