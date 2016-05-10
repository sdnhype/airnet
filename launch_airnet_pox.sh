#!/bin/bash

# Run example : ./launcher.sh usecases.toy_example usecases.toy_example_mapping

# Usage
#-------
if [ $# -ne 2 ]
then
    echo Usage: $0 control_program_file mapping_file
    exit 1
fi

#POX_DIR=~/pox
POX_DIR=~/These/pox

CTRL_MODULE=proto.$1
MAPPING_MODULE=proto.$2

# echo $CTRL_MODULE
# echo $MAPPING_MODULE

echo Running POX with embedded prototype...
# --host_tracker=ERROR
$POX_DIR/pox.py log.level --INFO --openflow.of_01=ERROR --openflow.discovery=ERROR --host_tracker=ERROR --openflow.topology=ERROR \
	log --file=$CTRL_MODULE.log\
	openflow.discovery --link_timeout=10 host_tracker --arpAware=3600 --arpReply=2 --pingLim=2 --timerInterval=3600 \
	topology openflow.topology \
	proto.infrastructure proto.runtime --control_program=$CTRL_MODULE --mapping_program=$MAPPING_MODULE \
	proto.arp_proxy proto.airnet py

