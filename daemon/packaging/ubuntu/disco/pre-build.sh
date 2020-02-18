# add debian build repository
apt-get update
apt-get install -y wget gnupg apt-utils

echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-build/xUbuntu_19.04/ /' > /etc/apt/sources.list.d/home:CZ-NIC:knot-resolver-build.list
wget -nv https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-build/xUbuntu_19.04/Release.key -O Release.key
apt-key add - < Release.key

apt-get update
apt-get upgrade -y
