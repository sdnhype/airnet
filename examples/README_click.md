# Click modular router

## What's click?

Click is a modular router toolkit.  We use it to implement AirNet's *Data Machines*.
See https://github.com/kohler/click for more information.

## Architecture

        --------------------
         AirNet Hypervisor
        --------------------
                |
        --------------------
           RYU Controller
        --------------------
                |
        --------------------
     Mininet VM ---- Click VM
        --------------------

## Configuration

1) Install a Linux-based VM for Click

    $ sudo aptitude update
    $ sudo aptitude upgrade
    $ sudo aptitude install build-essential

2) Clone and install the Click project

    $ git clone git://github.com/kohler/click.git
    $ cd click
    $ ./configure
    $ sudo make install

3) Configure the VMs interfaces

On each VM (Mininet and Click), configure three interfaces:

* _NAT interface_ to access Internet (e.g. eth0)
* _Host-only interface_ to enable SSH from the host (e.g. eth1)
* _Internal network interface_ to connect to other VMs (e.g. eth2)


**The Click VM internal interface address (e.g. eth2) must be configured with the same IP address as the _DataMachine_ IP address in the mapping file**. Moreover, make sure the internal interface is up and is in promiscuous mode.

    $ sudo ip addr add <ip_address> dev <intf>
    $ sudo ip link set dev <intf> up
    $ sudo ip link set dev <intf> promisc on

Note that for two DataMachines, two Click VMs are needed. In that case, the Mininet VM must have two internal interfaces: one for the Click VM1 and one for the Click VM2.


4) Define in Click the operation to apply on packets

See the Click documentation for details on that part. For example, in order to store packets arriving on interface eth2 in a queue and send them back on the same interface after a 100 ms delay, the content of the Click file (in the click/conf folder) could be:

    FromDevice(eth2) -> Queue(10) -> DelayShaper(0.1) -> ToDevice(eth2);


5) Start AirNet, RYU and Mininet.

    (localhost)$ ./launch_airnet_ryu.sh <click_usecase> <click_usecase_mapping>
    (localhost)$ ryu-manager --observe-links airnet_interface.py
    (mininet VM)$ sudo python click_usecase_topo.py <ryu_ip_address> <ryu_port>

6) Start Click

    $ ping -c1 <mininet_IP_addr> (so that the host can be detected by Ryu)
    $ sudo click click/conf/emptyDM.click
	$ sudo tcpdump -n -i eth2 (optional)

7) Run tests in Mininet (ping, wget...)

Redirected packets should appear in the Click VM tcpdump console.
