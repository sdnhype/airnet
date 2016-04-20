from pox.core import core

def host_nwAddr(host_name):
    return core.runtime.get_host_nwAddr(host_name)

def host_dlAddr(host_name):
    return core.runtime.get_host_dlAddr(host_name)

def host_to_nwAddr(nwAddr):
    if isinstance(nwAddr, str):
        return core.runtime.nwAddr_to_host(nwAddr)
    else:
        raise RuntimeError("expecting string value for nwAddr")

def host_to_dlAddr(dlAddr):
    pass

def nwAddr_to_host(nwAddr):
    pass

def dlAddr_to_host(nwAddr):
    pass


        
        
        
