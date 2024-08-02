#!/usr/bin/env bash
# enable CZ.NIC Labs Debian/Ubuntu repos - see https://pkg.labs.nic.cz/doc/
set -e

REPO=$1
if [ -z "${REPO}" ]; then
    echo "usage: $0 REPOSITORY"
    echo -e "\nPlease see: https://pkg.labs.nic.cz/doc/"
    exit 1
fi
if [ "$(whoami)" != "root" ]; then
    echo "ERROR: this script must be run as ROOT"
    echo -e "\nTry running with sudo:\n\n    sudo $0\n"
    exit 2
fi

# update apt metadata and install requirements
apt-get update
apt-get install -y apt-transport-https ca-certificates lsb-release wget

DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
CODENAME=$(lsb_release -sc)

echo "Enabling $REPO repo on $DISTRO $CODENAME..."
# get repo signing key
wget -O /usr/share/keyrings/cznic-labs-pkg.gpg https://pkg.labs.nic.cz/gpg
# create repo entry
echo "deb [signed-by=/usr/share/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/$REPO $CODENAME main" > /etc/apt/sources.list.d/cznic-labs-$REPO.list
# update apt metadata from the new repo
apt-get update
