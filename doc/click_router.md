# Click modular router

## What's click ?

Click is a toolkit used by datamachines to simulate operations on packets.
See also https://github.com/kohler/click for more information.

## Architecture

			---------------------
		  	AirNet Hypervisor
			---------------------
			         |
			---------------------
				 RYU Controller
			---------------------
			         |
			      VM mininet -- VM click


## Configuration

1 install a Linux-based VM for click
	- sudo aptitude update
	- sudo aptitude upgrade
	- sudo aptitude install build-essential

2 clone and install the click project
	- git clone git://github.com/kohler/click.git
	- cd click
	- ./configure
	- sudo make install

3 configure VMs interfaces

	+ For the mininet VM
		- NAT interface for internet access (e.g. eth0)
		- HostOnly interface for ssh connexion from the host (e.g. eth1)
		- Internal-network interface for connexion with the click VM (e.g. eth2)

	+ For the click VM
		- NAT interface for internet access (e.g. eth0)
		- HostOnly interface for ssh connexion from the host (e.g. eth1)
		- Internal-network interface for connexion with the mininet VM (e.g. eth2)

	The click VM internal interface address (e.g. eth2) should be the same as the
	datamachine ip address in the mapping file.
	- sudo ip addr add [ip_adress] dev [intf]

	For two datamachines, two click VMs are needed. In that case, the mininet VM should
	have two internal interfaces : one for the click VM1 (e.g. mininet1) and one for
	the click VM2 (e.g. mininet2).

	P.S: Make sure the click VM internal interface is up and is in promicuous mode.
	- sudo ip link set dev [intf] up
	- sudo ip link set dev [intf] promisc on

4 define in click the operation to apply on packets

	e.g. : Store packets arriving in [intf] in a queue
	 			 Send them back to [intf] after a 100 ms delay

	Content of toto.click configuration file in click/conf folder

			FromDevice(eth2) -> Queue(2) -> DelayShaper(0.1) -> ToDevice(eth2);


5 start AirNet, RYU and mininet topology

	- airnet$ ./launch_airnet_ryu.sh click.usecase click.usecase_mapping
	- ryu$ ryu-manager --observe-links airnet_interface.py
	- mininet$ sudo python click_topo.py [ryu_ip_address] 6633

6 start click
	- ping -c1 192.168.0.1 (so that the host can be detected by RYU)
	- sudo click click/conf/toto.click
	- sudo tcpdump -n -i eth2

7 run tests (ping, wget...)

	Redirected packets should appear in the click VM console
