# SPDX-License-Identifier: GPL-3.0-or-later

yum update -y
yum install -y wget epel-release

# add build repository
cd /etc/yum.repos.d/
wget https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/CentOS_7_EPEL/home:CZ-NIC:knot-resolver-latest.repo
