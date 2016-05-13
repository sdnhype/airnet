Installation de Ryu:
- installer les paquets suivant: sudo python-pip python-dev libxml2-dev libxslt1-dev python-paramiko 
                                python-webob python-routes
- a l'aide de pip installer les dependances duivantes:
       sudo pip install -U six oslo.config eventlet msgpack-python ovs==2.6.0.dev0

- cloner le depot git de ryu:
        git clone  https://github.com/osrg/ryu.git
- Dans notre cas il faudra copier les fichiers controller.py rest_client.py packetParser.py du depôt 
  dans le repertoire ryu/ryu/app.Il existe deja un fichier ofctl_rest.py dans ce repertoire il sera donc remplace      
- aller dans le repertoire ryu puis installer:
         sudo python setup.py install

Lancement de Ryu:         
Pour lancer Ryu :
    ryu-manager [--verbose] [--observe-links] liste_app_contrôle
            l'option verbose permet l'affichage de certaines infos
            l'option observe-links permet aux switchs de s'envoyer des paquets pour verifier l'etat des liens
            liste_app_contrôle :la liste des applications Ryu qu'on souhaite lancer. ex : ryu/app/ofctl_rest.py

Le lancement de ryu s'effectuera donc comme suit:
        ryu-manager --observe-links ryu/app/controller.py 
        en supposant qu'on se trouve dans le repertoire ryu (repertoire créé par le clonage du depot git de Ryu)
        pour quitter : Ctrl+c

Lancement du client airnet:
        le fichier a executer est stage_server.py avec comme parametres le fichier de controle et de mapping
        ex: python stage_server.py stagecases.twoFabrics stagecases.twoFabrics_mapping_bis
        pour quitter : Ctrl+c
        
Lancement de la topo mininet:
        le lancement de la topologie mininet se fait comme d'habitude en mode root:
        python fichier_de_topo ip_controleur port_controleur
        ex: sudo python topo_2_fabrics_bis.py 192.168.56.1 6633
        Il faut lancer Ryu et le client airnet avant de lancer la topo mininet
        

      