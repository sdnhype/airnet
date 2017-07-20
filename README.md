
## What is AirNet?

**AirNet** is a virtual network control language built on top of an *Edge-Fabric* abstraction model. It includes a hypervisor that supports high-level control policies composition as well as their mapping on the physical infrastructure. Generally speaking, AirNet can be seen as an orchestrator of different types of network services (static and dynamic control functions, transport and data functions) specified on top of an *edge-fabric* virtual network.

AirNet started as part of Messaoud Aouadj's PhD thesis at [Toulouse University](http://en.univ-toulouse.fr) (France) in the [IRIT](https://www.irit.fr) lab. More information on AirNet can be found in these research articles:

* *AirNet: the Edge-Fabric model as a virtual control plane*. Messaoud Aouadj, Emmanuel Lavinal, Thierry Desprats, Michelle Sibilla. In: International Workshop on Software-Driven Flexible and Agile Networking (SWFAN 2016), San Francisco, USA, 2016.
* *Composing data and control functions to ease virtual networks programmability*. Messaoud Aouadj, Emmanuel Lavinal, Thierry Desprats, Michelle Sibilla. In: IEEE/IFIP Network Operations and Management Symposium (NOMS 2016) Mini-Conference, Istanbul, Turkey, 2016.


## Requirements

* Python 2.7
* [virtualenv](https://virtualenv.pypa.io) (optional but recommended), a tool to create isolated Python environments
* [Flask](http://flask.pocoo.org), a micro webdevelopment framework for Python
* [Ryu](https://osrg.github.io/ryu), a Python SDN controller
* A network of OpenFlow switches (either a physical infrastructure or an emulated network thanks to [mininet](http://mininet.org)).

## Installation

### Installing AirNet and Ryu

In order to create an isolated Python environment, install `virtualenv` (if not already installed):

    $ [sudo] pip install virtualenv

Create a new environment and activate it:

    $ virtualenv airnetenv
    $ source airnetenv/bin/activate

Install the [Flask](http://flask.pocoo.org) micro web development framework and the [Ryu](https://osrg.github.io/ryu/) SDN controller (AirNet currently works on top of Ryu, other controllers will be integrated in the future):

    $ pip install flask
    $ pip install ryu

And finally, clone AirNet from github:

    $ git clone git://github.com/sdnhype/airnet.git
    $ cd airnet

That's it!

### Installing Mininet

You can test all the examples provided in the `examples` folder by using the [mininet](http://mininet.org) network emulator. We recommend you download the pre-packaged Mininet VM.

## Running the examples

For each example, you have a README file that includes:

* the virtual topology and the associated network control policies (`example.py`),
* the physical (mininet) topology (`example_topo.py` ),
* the virtual-to-physical mapping rules (`example_mapping.py`),
* the commands you can run on mininet to test the example.

For each AirNet program you wish to test, you need to go through three steps:

1- Run AirNet (in one terminal):

    $ launch_airnet_ryu.sh <example.py> <example_mapping.py>

2- Run Ryu (in another terminal)

    $ cd controllers/ryu/
    $ ryu-manager --observe-links airnet_interface.py

3- Run Mininet (in the VM)

    $ sudo python <example_topo.py> <contoller_IP_address> <controller_port>

You're then all set to test the network behavior in Mininet!



A good way to get started is to run the toy example included in the `examples/toyExample` folder.

## License

AirNet is distributed under the GNU General Public License v3.
