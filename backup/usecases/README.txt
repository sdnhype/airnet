
**********************
*** Use cases list ***
**********************

1)  staticFiltering        (static filtering on dst and app proto)
2)  dataCompress           (data function)
3)  dynAuthentication      (dyn ctrl function)
4)  dynAuthentication Bis  (dyn ctrl function)
4') dynAuthentication Ter  --> ne marche pas
5)  dynLoadBalancer        (dyn ctrl function)
6)  fabricComposition      (catch()+catch() and static filtering on dst)
7)  dataCap                (stats on dyn ctrl function)
8)  TODO.



****************************************************************
* staticFiltering.py: static filtering on dst and app protocol *
****************************************************************

                       WS   SSH_GW
                         \ /
                         [ED]
------------              |               -----------------
- Internet ----[EI]---[ Fabric ]---[EC]---- Corporate Net -
------------              |               -----------------
                         [EW]
                         /  \
                   -------  --------
                   - WiFI-   - WiFi -
                   - Pub -   - Priv -
                   -------   --------

Policies (by app flows):

- [ Internet, WiFi Pub and Priv ] <--> WS  : allow HTTP
- [ Internet, WiFi Pub and Priv ] <--> WS  : allow ICMP

- [ Internet, WiFi Pub and Priv ] <--> SSH_GW : allow SSH
- [ SSH_GW ]                      <--> Corporate Net : allow ALL

- [ Wifi Pub and Priv ]           <--> Internet : allow ALL
TODO - [ WiFi Priv ]              <--> Corporate Net : allow FTP

- drop other (e.g. Internet --> Corp Net)


--> Tested on topo_static_filtering.py physical topo

                                ws
                               /
   inet_h -- s1              s9 -- ssh_gw
               \            /
               s2 -- s3 -- s5 -- s7 -- priv_net_h
                 \        /
                  s4 -- s6 -- s8
                             /   \
                       wifipub_h   wifipriv_h
                       
                       
                       
********************************************************
* dataCompress.py: compress dataFct usecase, 2 DataFct *
********************************************************

                         
     client1--|  (compress)         (uncompress)                 
              |-----[IO]---[ fabric ]---[AC]----- server
     client2--|                              

_ client1 and client2 flows OK to server
_ 1 dataFct on IO to compress client1 and client2 flows
	-- no limit
	-- split on src adr
_ 1 dataFct on AC to uncompress flows toward server
	-- no limit
	-- split on src adr

_ tested on topo_4sw_3hosts.py physical topo

     h1--|
         |---[s1]----[s2]----[s3]----[s4]---h3
     h2--|


*************************************************************************
* dycAuthentication.py : authentication scenario 1, 1 DynamicControlFct *
*************************************************************************

                         Auth Server
-------------                 |
- Net Users --|             [AC1]                         
------------- |               |              |-- WS
              |---[IO]---[ Fabric ]---[AC2]--|
--------------|                              |-- CC
- Net Guests -|
--------------


- Users flows OK to WS and CC
- Initially, guests flows to WS and CC are dropped
- Guests flows OK to Auth Server
- 1 dyn ctrl funtion on AC1 : authenticate
  -- limit 1 & split src adr
  -- installs new policy on IO if packet received from Auth Server
     (new policy allowing guests to WS)

- tested on topo_10sw_5hosts.py physical topo

                                    |---[s8]---|---AS    
                                    |
users --|---[s1]---|           |---[s6]---[s7]----|           |---[s9]---WS
                   |---[s3] ---|                  |---[s5] ---| 
guests--|---[s2]---|           | -------[s4] -----|           |---[s10]---CC
                      				  



****************************************************************************
* dycAuthenticationBis.py : authentication scenario 2, 1 DynamicControlFct *
****************************************************************************

--> Compared to dycAuthentication: NO Auth Server, NO AC1 edge

------------- 
- Net Users --|                           
------------- |  (authenticate)             |-- WS
              |---[IO]---[ Fabric ]---[AC]--|
--------------|                             |-- CC
- Net Guests -|
--------------

- Users flows OK to WS and CC
- Guests flows KO to CC
- Guests flows to WS pass through authenticate network function
- 1 dyn ctrl funtion on IO : authenticate
  -- limit 1 & split src adr
  -- installs new policy on IO :
        if guest source belongs to white list, allow to WS, else drop
     
- tested on topo_9sw_4hosts.py physical topo

users---[s1]----|          |---[s5]---[s6]---|          |---[s8]---WS
                |---[s3]---|                 |---[s7]---| 
guests---[s2]---|          |--------[s4] ----|          |---[s9]---CC



****************************************************************************
* dycAuthenticationBis.py : authentication scenario 3, 1 DynamicControlFct *
****************************************************************************

--> Compared to usecase 01 bis: AS edge with dyn ctrl fct

-------------            (authenticate)
- Net Users --|             [AS]              
------------- |              |              |-- WS
              |---[IO]---[ Fabric ]---[AC]--|
--------------|                             |-- CC
- Net Guests -|
--------------

- Users flows OK to WS and CC
- Guests flows KO to CC
- Guests flows OK to AS
- 1 dyn ctrl funtion on AS : authenticate
  -- limit 1 & split onsrc adr
  -- installs new policy on IO :
        if guest source belongs to white list, allow to WS, else drop
      
---> NE MARCHE PAS sur topo_9sw_4hosts.py physical topo
     car AS mapped on same switches than IO.
     Du coup, regles en conflit : forward vers fabric (to AS)
                               vs forward vers controler (authenticate fct)

users---[s1]----|          |---[s5]---[s6]---|          |---[s8]---WS
                |---[s3]---|                 |---[s7]---| 
guests---[s2]---|          |--------[s4] ----|          |---[s9]---CC



*******************************************************************
* dycLoadBalancer.py : dynamic load balancer, 1 DynamicControlFct *
*******************************************************************

     client1--|
     client2--|                               |--- WS1
              |-----[IO]---[ fabric ]---[LB]--|
     client3--|                               |--- WS2
     client4--|                              

_ clients flows OK towards public server
_ depending on client src adr, the flow will be directed either to WS1 or WS2
_ 1 dycControlFct on LB:
	--limit1 & split on src adr
	--install new policies on LB to forward flows either towards WS1 or WS2

_ tested on topo_8sw_6hosts.py physical topo

client1---|
          |---[s1]---|
client2---|          |          |--[s5]--[s6]--|                 |---WS1
                     |---[s3]---|              |---[s7]---[s8]---|
client3---|          |          |-----[s4]-----|                 |---WS2
          |---[s2]---|
client4---|



*********************************************************
* fabricComposition.py : fabric primitives composition  *
*********************************************************

----------
staff_net-|---|
----------    |
              |---[users_IO]----|
----------    |                 |                                
guests_net-|--|                 |                                   |--- WS1
----------                      |              |---[users_egress]---|
                                |---[fabric]---|                    |--- WS2
-----------                     |              |
admins_net-|-----[admins_IO]----|              |---[admins_egress]--- DB
-----------


_ staff_net flows OK to WS1
_ guests_net flows OK to WS2
_ admins_net flows OK to DB

_ tested on topo_10sw_6hosts.py physical topo


staff_net---|---[s1]---|
	                   |
guests_net--|---[s2]-- |                                                      |--- WS1
		               |          |----[s5]----[s6]----|          |---[s11]---|--- WS2
		               |---[s4]---|	                   |---[s7]---|
                       |          |--[s8]--[s9]--[s10]-|          |---[s12]-------- DB
admins_net---|---[s3]--|




**********************************************
* dataCap.py : dyn ctrl function with stats  *
**********************************************

                        
     client1--|
              |-----[IO]---[ fabric ]---[AC]----- server
     client2--|

_ client1 and client2 can receive a maximum 2000 bytes per minute:
	-if a client exceeds this threshold, he will be  blocked for the next minute
	-after a blocking minute, he'll have again the opportunity to send data


_ tested on topo_4sw_3hosts.py physical topo

     h1--|
         |---[s1]----[s2]----[s3]----[s4]---h3
     h2--|



