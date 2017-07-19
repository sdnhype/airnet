from mapping import Mapping

"""
* Virtual topology

client1--|
         |---[IO]---[ fabric ]---[AC]--- server
client2--|

* Physical topology

h1(192.168.0.11)--|
                  |-- s1 -- s2 -- s3 -- s4 -- s5 ---- h3 (172.16.0.11)
h2(192.168.0.12)--|

* Mapping

client1 --> h1, client2 --> h2, server  --> h3
Edge IO --> s1
Edge AC --> s5
Fabric  --> s2, s3, s4

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1")
        self.addEdgeMap("AC", "s5")
        self.addFabricMap("fabric", "s2", "s3", "s4")
        self.addHostMap("client1", "192.168.0.11")
        self.addHostMap("client2", "192.168.0.12")
        self.addHostMap("server", "172.16.0.11")

def main():
    return Mymapping()
