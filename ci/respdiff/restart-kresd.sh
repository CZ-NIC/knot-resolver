#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

exec > /dev/null
exec 2>&1

killall -w kresd
rm -f '*.mdb'
$PREFIX/sbin/kresd -n -q -c $(pwd)/ci/respdiff/kresd.config &>>kresd.log &

# wait until socket is receiving connections
sleep 1
