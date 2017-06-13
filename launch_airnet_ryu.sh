#!/bin/bash

# Usage
#-------
if [ $# -ne 2 ]
then
    echo Usage: $0 control_program_file mapping_file
    exit 1
fi

export PYTHONPATH=$PYTHONPATH:./examples/

CTRL_MODULE=$1
MAPPING_MODULE=$2
AIRNET_DIR=airnet

echo "Starting AIRNET Hypervisor with RYU Controller ....... "

python $AIRNET_DIR/restServer_controller.py $CTRL_MODULE $MAPPING_MODULE
