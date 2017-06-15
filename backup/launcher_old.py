#!/usr/bin/python

import sys
import subprocess
import os


def main():
    
    control_module = sys.argv[1]
    control_module = "proto." + control_module[:-3]
    mapping_module = sys.argv[2]
    mapping_module = "proto." + mapping_module[:-3]
   
    # debug
    print control_module
    print mapping_module
    print os.path.dirname(os.path.realpath(__file__))

    subprocess.call(["~/pox/pox.py", "log.level", "--WARNING", 
                     "forwarding.l2_learning", 
                     "openflow.discovery", 
                     "host_tracker", 
                     "topology", 
                     "openflow.topology", 
                     "proto.infrastructure",
                     "proto.arp_proxy", 
                     "proto.runtime", 
                     "--control_program={}".format(control_module), 
                     "--mapping_program={}".format(mapping_module),
                     "py"])

if __name__ == '__main__':
    main()
