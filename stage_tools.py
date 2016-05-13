def countOfMessages(of_messages):
    cpt = 0
    for dpid, messages in of_messages.iteritems():
        cpt += len(messages)
    return cpt

def singleton(f):
    return f()

def match_from_packet(packet):
    """
    le paquet peut etre un paquet pox ou un dictionnaire
    """
    from stage_language import match
    import ast
    my_match = match()
    if isinstance(packet, dict):
        #ici il s'agit de {'dpid':..,'packet':{'ipv4':{......},'tcp':{....},...},'port':..}
        protos = packet.get('packet')
        protos = ast.literal_eval(str(protos))
        if 'ipv4' in protos:
            ip = protos.get('ipv4')
            my_match.map["nw_src"] = ip.get('src')
            my_match.map["nw_dst"] = ip.get('dst')
        if 'tcp' in protos:
            tcp = protos.get('tcp')
            my_match.map["tp_src"] = tcp.get('src_port')
            my_match.map["tp_dst"] = tcp.get('dst_port')
    else:
        ip = packet.find('ipv4')
        if ip:
            my_match.map["nw_src"] = ip.srcip.toStr()
            my_match.map["nw_dst"] = ip.dstip.toStr()
        tcp = packet.find('tcp')
        if tcp:
            my_match.map["tp_src"] = tcp.srcport
            my_match.map["tp_dst"] = tcp.dstport
    
    return my_match


        
        
        