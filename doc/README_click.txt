****************************************************************
* README for usescases with Data Machines (click router in VM) *
****************************************************************

1. Télecharger une VM Linux pouc click (ex: VM mininet basee sur Ubuntu 14.04)
	>sudo apt-get update
	>sudo apt-get upgrade
	>sudo apt-get install build-essential

2. Cloner Click à partir de GitHub et l’installer
	>git clone git://github.com/kohler/click.git
	>cd click
	>./configure
        >sudo make install

3: Configurer les interfaces des VMs CLICK

	Pour chaque VM, 3 interfaces:
	  - NAT pour pouvoir accéder au net (e.g. eth0)
	  - Une interface HostOnly (réseau privé hôte) pour la connexion ssh (e.g. eth1)
	  - Une interface Internal-Network (réseau interne)  pour une connexion
	    entre la VM click et la VM mininet (e.g. eth2)

  La dernière interface est configurée en statique avec une @ IP utilisée dans le mapping
  airnet - mininet.

  exemple :
  sudo ip addr add 192.168.1.11/16 dev eth2
  sudo ip link set dev eth2 up
  --> peut être configuré en dur dans fichier /etc/network/interfaces :

      auto eth2
      iface eth2 inet static
      address 192.168.1.11
      netmask 255.255.0.0

4. Configurer la VM mininet pour avoir les "internal networks" vers les VM CLICK

   - 1 internal network entre VM1 Click et VM mininet (ex: mininet1)
   - 1 internal network entre VM2 Click et VM mininet (ex: mininet2)

   ATTENTION : les VM click et mininet doivent avoir leur interface internal
               network en mode promiscuous (sinon les paquets qui ne leur sont
               destinés ne remontent pas dans le kernel !)

  La VM mininet aura donc au moins 4 interfaces :
    - eth0  NAT vers l'exterieur
    - eth1  host only network
    - eth2  internal network vers VM Click
    - eth3  internal network vers VM Click

   ATTENTION : s'assurer que eth2 et eth3 sont UP.
               ($ sudo ip link set dev eth2 up)

5. spécifier une configuration click (une vnf) sur les VM Click

***********************************************************
*** extrait fichier click: (extension du fichier .click) **
***********************************************************
FromDevice(eth2) -> Queue(2000) -> ToDevice(eth2);


6. Lancer AirNet (avec le use case click.py et click_mapping.py)

	>./launcher.sh usecases.click usecases.click_mapping

7. Lancer mininet

	>sudo python topo_click.py 192.168.56.x 6633

8. Lancer click

	installer la config click en mode kernel
		> sudo click-install click/conf/file_name.click
	lancer tcpdump por charger pcap
		> tcpdump -i eth2
	faire un ping pour que le module host_tracker détecte le host click
		> ping 192.168.0.1

9. Installer les rules
	> core.airnet.init()

10. Tester avec ping et dpctl dump-flows.

(la connectivité doit fonctionner et les paquets doivent apparaitre sur tcpdump
des VM click)
