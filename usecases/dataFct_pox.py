from pox.core import core
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of 


"""
	      dm
	      ||
c1---|1	 3||4	      |-----s3-----|			  
	 |----s1--5--s2---|	           |---s6---s7---server
c2---|2	              |---s4--s5---|

Tests:  ping c1 <--> server (via dm)			

"""


class Runtime():
    _core_name = "runtime"
    
    def init(self):
        
        of_messages = {}
        for dpid in range(1,8):
            # 1 for each sw
            of_messages[dpid] = []
            of_messages[dpid].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            of_messages[dpid].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            #ALLER
            my_match = of.ofp_match()
            my_match.nw_src = IPAddr("192.168.5.12")
            my_match.dl_type = 0x0800
            of_messages[dpid][0].match = my_match
            #RETOUR
            my_match = of.ofp_match()
            my_match.nw_dst = IPAddr("192.168.5.12")
            my_match.dl_type = 0x0800
            of_messages[dpid][1].match = my_match
        
        #DM    
        of_messages[1][0].match.in_port = 1
        of_messages[1][0].actions.append(of.ofp_action_output(port=3))
        of_messages[1].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        my_match = of.ofp_match()
        my_match.nw_src = IPAddr("192.168.5.12")
        my_match.in_port = 4
        my_match.dl_type = 0x0800
        of_messages[1][2].match = my_match
        of_messages[1][2].actions.append(of.ofp_action_output(port=5))
            
            
        #ALLER    
        of_messages[2][0].actions.append(of.ofp_action_output(port=2))
        of_messages[3][0].actions.append(of.ofp_action_output(port=2))
        of_messages[6][0].actions.append(of.ofp_action_output(port=3))
        of_messages[7][0].actions.append(of.ofp_action_output(port=1))
        #RETOUR    
        of_messages[1][1].actions.append(of.ofp_action_output(port=1))
        of_messages[2][1].actions.append(of.ofp_action_output(port=1))
        of_messages[3][1].actions.append(of.ofp_action_output(port=1))
        of_messages[6][1].actions.append(of.ofp_action_output(port=1))
        of_messages[7][1].actions.append(of.ofp_action_output(port=2))
        #Send messages
        for dpid, of_msgs in of_messages.iteritems():
            for msg in of_msgs:
                if not core.openflow.sendToDPID(dpid, msg):
                    raise RuntimeError("the OpenFlow message was not sent")

 
def launch ():      
    core.registerNew(Runtime)
 
