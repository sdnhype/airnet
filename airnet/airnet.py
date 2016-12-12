from pox.core import core
import sys

log = core.getLogger()

class AirNet(object):
    """
    at the end, all components (runtime, infrastructure, etc.) will be placed in this airnet component 
    """
    
    _core_name = "airnet"
    
    def init(self):
        core.arp_proxy.start()
        core.runtime.enforce_policies()
        core.infrastructure.runtime_mode = True
        
    def stop_timers(self):
        """
        For debug
        """
        core.runtime.stop_timers()
     
    def exit(self):
        core.runtime.stop_timers()
        core.infrastructure.runtime_mode = False
        core.quit()
        raise SystemExit
            
        
def launch():
    core.registerNew(AirNet)