

1: Télecharger une VM Ubuntu 14.04 pour click
	>sudo apt-get update
	>sudo apt-get upgrade
	>sudo apt-get install build-essential

2: Cloner Click à partir de GitHub et l’installer
	>git clone git://github.com/kohler/click.git
	>cd click
	>./configure 
	>sudo make install

3: Configurer les interfaces des VMs

	Pour chaque VM trois interfaces:
		- NAT pour pouvoir accéder au net (e.g., 10.0.2.15)
		- Une interface HostOnly pour la connexion ssh (e.g., 192.168.56.101)
		- Une interface Internal-Network pour une connexion entre les deux VMs (e.g., VM eth1 192.168.0.22)

**********************************************************************
*** extrait du fichier de conf pour les interfaces *******************
**********************************************************************
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto et0
iface eth0 inet dhcp
auto eth2
iface eth2 inet dhcp
auto eth1
iface eth1 inet manual
        up ip link set eth1 up
***********************************************************************
        

4: spécifier une configuration click (une vnf)

**********************************************************
*** extrait fichier click: (extension du fichier .click)**
**********************************************************

FromDevice(eth1) -> Queue(2000) -> ToDevice(ethic);

**********************************************************
**********************************************************


5: Lancer AirNet (avec le use case click.py et click_mapping.py)

	>./launcher.py usecases.click usecases.click_mapping

6: Lancer mininet

	>sudo python topo_click.py 192.168.56.1 6633

7: lancer click

	installer la config click en mode kernel
		>sudo click-install click/conf/file_name.click
	lancer tcpdump por charger pcap
		>tcpdump eth1
	faire un ping pour que le module host_tracker détecte le host click
		> ping 192.168.0.1

8: installer les rules
	>core.airnet.init()

9: Tester avec ping et dpctl dump-flows.

