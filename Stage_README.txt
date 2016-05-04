Installation de Ryu:
- installer les paquets suivant: python-pip python-dev libxml2-dev libxslt1-dev python-paramiko 
                                python-webob python-routes
- a l'aide de pip installer les dependances duivantes:
        pip install -U six oslo.config eventlet msgpack-python ovs==2.6.0.dev0

- cloner le depot git de ryu:
        git clone  https://github.com/osrg/ryu.git
        
- aller dans le repertoire ryu puis installer:
         python setup.py install

Lancement de Ryu:         
Pour lancer Ryu :
    ryu-manager [--verbose] [--observe-links] liste_app_contrôle
            l'option verbose permet l'affichage de certaines infos
            l'option observe-links permet aux switchs de s'envoyer des paquets pour verifier l'etat des liens
            liste_app_contrôle :la liste des applications Ryu qu'on souhaite lancer. ex : ryu/app/ofctl_rest.py

Dans notre cas il faudra copier les fichiers ofctl_rest.py rest_client.py packetParser.py et appRyu.py du depôt 
dans le repertoire ryu/ryu/app.Il existe deja un fichier ofctl_rest.py dans ce repertoire il sera donc remplace

Le lancement de ryu s'effectuera donc comme suit:
        ryu-manager --observe-links ryu/app/ofctl_rest.py ryu/app/appRyu.py 
        en supposant qu'on se trouve dans le repertoire ryu (repertoire créé par le clonage du depot git de Ryu)
       


