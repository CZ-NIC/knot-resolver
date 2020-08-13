#!/bin/sh

# make errors fatal
set -e

# assert that we are running from the correct directory
git_root="$(git rev-parse --show-toplevel)"
if ! echo "$PWD" | grep "^$git_root" > /dev/null; then
    echo "Must be running from within the knot resolver git repository!"
    exit 1
fi
cd "$git_root/modules/sysrepo"

# remove existing schema
if sysrepoctl -l | grep cznic-resolver-knot > /dev/null; then
    echo "Uninstalling existing schema..."
    sysrepoctl -u cznic-resolver-knot
fi

# install new schema
echo "Installing new schema..."
sysrepoctl -i yang/yang-modules/cznic-resolver-knot.yang -s yang/yang-modules

# import data
echo "Importing data..."
sysrepocfg --import=yang/examples/config-data.json --datastore running --module cznic-resolver-common
