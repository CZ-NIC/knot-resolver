#!/bin/bash

# fail fast
set -e

# check for root
if test "$(id -u)" -ne 0; then
    echo "Must be run as root"
    exit 1
fi


systemctl start knot-resolver.service

# FIXME remove after implementing sd_notify in manager
sleep 10

# check that the resolvers are actually running
kdig @127.0.0.1 nic.cz