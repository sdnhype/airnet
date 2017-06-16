from pox.core import core
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of 

"""
TODO:
"""
class Runtime():
    _core_name = "runtime"
    
    def init(self):
        
        of_messages = {}
        switches =[1, 2, 4, 9, 10, 11]
        for switch in switches:
            of_messages[switch] = []
            of_messages[switch].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            of_messages[switch].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            of_messages[switch].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            of_messages[switch].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
            #ALLER
            my_match = of.ofp_match()
            my_match.nw_dst = IPAddr("192.168.15.13")
            my_match.dl_type = 0x0800
            of_messages[switch][0].match = my_match
            my_match = of.ofp_match()
            my_match.nw_dst = IPAddr("192.168.15.14")
            my_match.dl_type = 0x0800
            of_messages[switch][1].match = my_match
            #RETOUR
            my_match = of.ofp_match()
            my_match.nw_dst = IPAddr("192.168.15.11")
            my_match.dl_type = 0x0800
            of_messages[switch][2].match = my_match
            my_match = of.ofp_match()
            my_match.nw_dst = IPAddr("192.168.15.12")
            my_match.dl_type = 0x0800
            of_messages[switch][3].match = my_match
        
        
        #ALLER   
        of_messages[1][0].actions.append(of.ofp_action_output(port=3))
        of_messages[2][0].actions.append(of.ofp_action_output(port=2))
        of_messages[4][0].actions.append(of.ofp_action_output(port=2))
        of_messages[1][1].actions.append(of.ofp_action_output(port=3))
        of_messages[2][1].actions.append(of.ofp_action_output(port=2))
        of_messages[4][1].actions.append(of.ofp_action_output(port=2))
        of_messages[9][0].actions.append(of.ofp_action_output(port=4))
        of_messages[9][1].actions.append(of.ofp_action_output(port=5))
        of_messages[10][0].actions.append(of.ofp_action_output(port=2))
        of_messages[11][1].actions.append(of.ofp_action_output(port=2))
        

        #RETOUR    
        of_messages[2][2].actions.append(of.ofp_action_output(port=1))
        of_messages[4][2].actions.append(of.ofp_action_output(port=1))
        of_messages[2][3].actions.append(of.ofp_action_output(port=1))
        of_messages[4][3].actions.append(of.ofp_action_output(port=1))
        of_messages[9][2].actions.append(of.ofp_action_output(port=1))
        of_messages[9][3].actions.append(of.ofp_action_output(port=1))
        of_messages[10][2].actions.append(of.ofp_action_output(port=1))
        of_messages[10][3].actions.append(of.ofp_action_output(port=1))
        of_messages[11][2].actions.append(of.ofp_action_output(port=1))
        of_messages[11][3].actions.append(of.ofp_action_output(port=1))
        of_messages[1][2].actions.append(of.ofp_action_output(port=1))
        of_messages[1][3].actions.append(of.ofp_action_output(port=2))
        
        
        of_messages[10].pop(1)
        of_messages[11].pop(0)
        
        #DM
        of_messages[3] =[]
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        of_messages[3].append(of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT))
        
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.13")
        my_match.dl_type = 0x0800    
        my_match.in_port = 1
        of_messages[3][0].match = my_match
        of_messages[3][0].actions.append(of.ofp_action_output(port=4))
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.13")
        my_match.dl_type = 0x0800    
        my_match.in_port = 5
        of_messages[3][1].match = my_match
        of_messages[3][1].actions.append(of.ofp_action_output(port=2))
        
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.14")
        my_match.dl_type = 0x0800    
        my_match.in_port = 1
        of_messages[3][2].match = my_match
        of_messages[3][2].actions.append(of.ofp_action_output(port=4))
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.14")
        my_match.dl_type = 0x0800    
        my_match.in_port = 5
        of_messages[3][3].match = my_match
        of_messages[3][3].actions.append(of.ofp_action_output(port=2))
        
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.11")
        my_match.dl_type = 0x0800    
        my_match.in_port = 2
        of_messages[3][4].match = my_match
        of_messages[3][4].actions.append(of.ofp_action_output(port=5))
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.11")
        my_match.dl_type = 0x0800    
        my_match.in_port = 4
        of_messages[3][5].match = my_match
        of_messages[3][5].actions.append(of.ofp_action_output(port=1))
        
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.12")
        my_match.dl_type = 0x0800    
        my_match.in_port = 2
        of_messages[3][6].match = my_match
        of_messages[3][6].actions.append(of.ofp_action_output(port=5))
        my_match = of.ofp_match()
        my_match.nw_dst = IPAddr("192.168.15.12")
        my_match.dl_type = 0x0800    
        my_match.in_port = 4
        of_messages[3][7].match = my_match
        of_messages[3][7].actions.append(of.ofp_action_output(port=1))
                  
        
        #Send messages
        cpt_messages = 0
        for dpid, of_msgs in of_messages.iteritems():
            cpt_messages += len(of_msgs)
            for msg in of_msgs:
                if not core.openflow.sendToDPID(dpid, msg):
                    raise RuntimeError("the OpenFlow message was not sent")
        print "number of installed rules == " + str(cpt_messages)

 
def launch ():      
    core.registerNew(Runtime)
 
