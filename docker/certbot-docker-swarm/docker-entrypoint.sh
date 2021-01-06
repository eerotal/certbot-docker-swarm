#!/bin/sh

. /root/config.sh

set -e

# Make sure the Docker socket is available.
if [ ! -e "${DOCKER_SOCK}" ]; then
    printf "[ERROR] You must mount the Docker socket at ${DOCKER_SOCK}.\n"
    exit 1
fi

if [ "$1" == "" ]; then
    sh main.sh
elif [ "$1" == "shell" ]; then
    sh
elif [ "$1" == "dump-config" ]; then
    shift 1
    python3 dump-config.py $@
fi
