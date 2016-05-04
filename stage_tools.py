def countOfMessages(of_messages):
    cpt = 0
    for dpid, messages in of_messages.iteritems():
        cpt += len(messages)
    return cpt

def singleton(f):
    return f()

def match_from_packet(packet):
    """
    """
    from language import match
    my_match = match()
    ip = packet.find('ipv4')
    if ip:
        my_match.map["nw_src"] = ip.srcip.toStr()
        my_match.map["nw_dst"] = ip.dstip.toStr()
    tcp = packet.find('tcp')
    if tcp:
        my_match.map["tp_src"] = tcp.srcport
        my_match.map["tp_dst"] = tcp.dstport
    
    return my_match


        
        
        