**********
* AirNet *
**********

Licence -> TODO.

What is AirNet -> TODO.

***************************
* How to run the usecases *
***************************

1) Run the POX controller
==========================

Use the launcher script, passing the usescase files as arguments.
For example:

$ ./launcher.sh usecases.fabric_composition usecases.fabric_composition_mapping

--> You should obtain the POX CLI.

2) Run Mininet
===============

$ cd mininet/custom/topos/

- Choose a mininet topology: topo_4sw_2hosts, topo_10sw_4hosts...
- Execute the Mininet's startup code passing the controller's IP and port as arguments:
For example: 

$ sudo python topo_10sw_4hosts.py 127.0.0.1 6633
or 
$ sudo ./topo_10sw_4hosts.py 127.0.0.1 6633

--> Once the ping reachability tests are done, you should get the Mininet CLI.

3) Tests
=========

- Check physical infrastructure within controller:

POX> core.infrastructure.view()
--> You should get the mininet's topology.

- Check OpenFlow rules within Mininet:

mininet> dpctl dump-flows
--> All tables should be empty.

- Start ARP Proxy

POX> core.arp_proxy.start()

- Enforce proactive policies form AirNet/POX to Mininet:

POX> core.runtime.enforce_policies()

- Check OpenFlow rules within Mininet:

mininet> dpctl dump-flows
--> Rules should be installed on the switches...

- Test connectivity according to usecase.

Example for the "fabric composition" use case :

----------------------------------------
mininet> staff_net ping -c1 WS1
PING 141.115.28.12 (141.115.28.12) 56(84) bytes of data.
64 bytes from 141.115.28.12: icmp_seq=1 ttl=64 time=1.18 ms

--- 141.115.28.12 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.185/1.185/1.185/0.000 ms

----------------------------------------
mininet> staff_net ping -c1 DB
PING 141.115.28.11 (141.115.28.11) 56(84) bytes of data.

--- 141.115.28.11 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

----------------------------------------
mininet> admins_net ping -c1 DB
PING 141.115.28.11 (141.115.28.11) 56(84) bytes of data.
64 bytes from 141.115.28.11: icmp_seq=1 ttl=64 time=1.58 ms

--- 141.115.28.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.585/1.585/1.585/0.000 ms


***----------------------------------------------***
***----------------------------------------------***
---Example: Data Function use case
-Control module: netFct
-Mapping module: netFct_mapping
-Physical topology: topo_4sw_2hosts
----------------------------------------------
----------------------------------------------

POX>core.runtime.enforce_policies()
----------------------------------------------
mininet> xterm h1 h2 h3
----------------------------------------------
h3> cd
h3> python -m SimpleHTTPServer 8080
----------------------------------------------
h1> ping -c1 192.168.0.50
PING 192.168.0.50 (192.168.0.50) 56(84) bytes of data.
64 bytes from 192.168.0.50: icmp_seq=1 ttl=64 time=16.8 ms

--- 192.168.0.50 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 16.891/16.891/16.891/0.000 ms

POX> --- DataFct foo ---
packet ip_src: 192.168.0.11 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1}
packet ttl == 64
modifying ...
new ttl 66

--- DataFct bar ---
packet ip_src: 192.168.0.11 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1}
packet ttl == 66
----------------------------------------------
h2>cd
h2>cd test
h2> wget http://192.168.0.50:8080/test.txt
--2015-07-23 04:27:45--  http://192.168.0.50:8080/test.txt
Connecting to 192.168.0.50:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11 [text/plain]
Saving to: ‘test.txt.1’

100%[======================================>] 11          --.-K/s   in 0s      

2015-07-23 04:27:45 (1.21 MB/s) - ‘test.txt.1’ saved [11/11]

POX>--- DataFct foo ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 1}
packet ttl == 64
modifying ...
new ttl 66

--- DataFct bar ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 1}
packet ttl == 66

--- DataFct foo ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 2}
packet ttl == 64
modifying ...
new ttl 66

--- DataFct bar ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 2}
packet ttl == 66

--- DataFct bar ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 3}
packet ttl == 64

--- DataFct bar ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 4}
packet ttl == 64

--- DataFct bar ---
packet ip_src: 192.168.0.12 | packet ip_dst: 192.168.0.50
nb_packets == {'192.168.0.11': 1, '192.168.0.12': 5}
packet ttl == 64



***----------------------------------------------***
***----------------------------------------------***
---Example: Dynamic Control Function use case
-Control module: DynamicFct
-Mapping module: DynamicFct_mapping
-Physical topology: topo_8sw_6hosts
-ARP issues:
h1 and h3 can comminicate with h5
h2 and h4 can comminicate with h6
-Public IP server: 192.168.0.50

----------------------------------------------
----------------------------------------------

POX>core.runtime.enforce_policies()
----------------------------------------------
mininet> xterm h1 h2 h3 h4 h5 h6
----------------------------------------------
h5>ifconfig
h5-eth0   Link encap:Ethernet  HWaddr 6e:6c:2c:a2:82:1a  
          inet addr:192.168.0.51  Bcast:192.168.255.255  Mask:255.255.0.0
h5>python -m SimpleHTTPServer 8080
----------------------------------------------
h6>ifconfig
h6-eth0   Link encap:Ethernet  HWaddr aa:01:6a:4d:03:4b  
          inet addr:192.168.0.52  Bcast:192.168.255.255  Mask:255.255.0.0
h6>python -m SimpleHTTPServer 8080
----------------------------------------------
h1> ping -c1 192.168.0.50
PING 192.168.0.50 (192.168.0.50) 56(84) bytes of data.
64 bytes from 192.168.0.50: icmp_seq=1 ttl=64 time=44.2 ms

--- 192.168.0.50 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.296/44.296/44.296/0.000 ms

POX> flows coming from 192.168.0.11 are redirected towards WS1

*** s1 ***
NXST_FLOW reply (xid=0x4):
 cookie=0x0, duration=47.644s, table=0, n_packets=0, n_bytes=0, idle_age=47, priority=5,ip,nw_src=192.168.0.11,nw_dst=192.168.0.50 actions=mod_nw_dst:192.168.0.51,output:3
 cookie=0x0, duration=172.649s, table=0, n_packets=0, n_bytes=0, idle_age=172, priority=2,ip,nw_dst=192.168.0.12 actions=output:2
 cookie=0x0, duration=172.649s, table=0, n_packets=1, n_bytes=98, idle_age=47, priority=4,ip,nw_dst=192.168.0.50 actions=CONTROLLER:65535
 cookie=0x0, duration=172.649s, table=0, n_packets=1, n_bytes=98, idle_age=47, priority=3,ip,nw_dst=192.168.0.11 actions=output:1
 cookie=0x0, duration=172.649s, table=0, n_packets=30, n_bytes=1230, idle_age=3, priority=1 actions=drop

----------------------------------------------

h1> wget http://192.168.0.50:8080/test.txt
--2015-07-23 07:03:22--  http://192.168.0.50:8080/test.txt
Connecting to 192.168.0.50:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11 [text/plain]
Saving to: ‘test.txt’

100%[======================================>] 11          --.-K/s   in 0s      

2015-07-23 07:03:22 (1.15 MB/s) - ‘test.txt’ saved [11/11]

h5>192.168.0.11 - - [23/Jul/2015 07:03:22] "GET /test.txt HTTP/1.1" 200 -

----------------------------------------------
h3>wget http://192.168.0.50:8080/test.txt
--2015-07-23 07:05:46--  http://192.168.0.50:8080/test.txt
Connecting to 192.168.0.50:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11 [text/plain]
Saving to: ‘test.txt.1’

100%[======================================>] 11          --.-K/s   in 0s      

2015-07-23 07:05:47 (1.04 MB/s) - ‘test.txt.1’ saved [11/11]

h5>192.168.0.13 - - [23/Jul/2015 07:05:47] "GET /test.txt HTTP/1.1" 200 -

POX> flows coming from 192.168.0.13 are redirected towards WS1

----------------------------------------------

h2>wget http://192.168.0.50:8080/test.txt
--2015-07-23 07:07:07--  http://192.168.0.50:8080/test.txt
Connecting to 192.168.0.50:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11 [text/plain]
Saving to: ‘test.txt.2’

100%[======================================>] 11          --.-K/s   in 0s      

2015-07-23 07:07:08 (903 KB/s) - ‘test.txt.2’ saved [11/11]

h6>192.168.0.12 - - [23/Jul/2015 07:07:08] "GET /test.txt HTTP/1.1" 200 -

h2> flows coming from 192.168.0.12 are redirected towards WS2
----------------------------------------------

h4>wget http://192.168.0.50:8080/test.txt
--2015-07-23 07:07:33--  http://192.168.0.50:8080/test.txt
Connecting to 192.168.0.50:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11 [text/plain]
Saving to: ‘test.txt.3’

100%[======================================>] 11          --.-K/s   in 0s      

2015-07-23 07:07:33 (1.23 MB/s) - ‘test.txt.3’ saved [11/11]

h6>192.168.0.14 - - [23/Jul/2015 07:07:33] "GET /test.txt HTTP/1.1" 200 -

h4> flows coming from 192.168.0.14 are redirected towards WS2
