#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# $1 == udp/tcp/tls, it selects configuration file to use
# respdiff scripts must be present in /var/opt/respdiff
set -o errexit -o nounset -o xtrace

NDIFFREPRO=3

wget -qO- https://gitlab.labs.nic.cz/knot/respdiff/snippets/238/raw?inline=false | head -n 5000 > /tmp/queries.txt
mkdir results
rm -rf respdiff.db

CONFIG="$(pwd)/ci/respdiff/respdiff-${1}.conf"
/var/opt/respdiff/qprep.py respdiff.db < /tmp/queries.txt
time /var/opt/respdiff/orchestrator.py respdiff.db -c "${CONFIG}"
time /var/opt/respdiff/msgdiff.py respdiff.db -c "${CONFIG}"
for i in $(seq $NDIFFREPRO); do
	time /var/opt/respdiff/diffrepro.py -c "${CONFIG}" respdiff.db
done
/var/opt/respdiff/diffsum.py respdiff.db -c "${CONFIG}" > results/respdiff.txt
/var/opt/respdiff/histogram.py respdiff.db -c "${CONFIG}" -o results/histogram.svg
: minimize LMDB and log size so they can be effectively archived
mkdir results/respdiff.db
mdb_copy -c respdiff.db results/respdiff.db
xz -9 results/respdiff.db/data.mdb
xz kresd.log
