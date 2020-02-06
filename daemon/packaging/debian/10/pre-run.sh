apt-get update
apt-get install -y wget gnupg apt-utils

wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb
dpkg -i knot-resolver-release.deb

apt-get update
