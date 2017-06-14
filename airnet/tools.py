
def countOfMessages(of_messages):
    cpt = 0
    for dpid, messages in of_messages.iteritems():
        cpt += len(messages)
    return cpt
