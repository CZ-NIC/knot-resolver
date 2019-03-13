#!/bin/sh
exec > /dev/null
exec 2>&1

killall -w kresd
rm -f '*.mdb'
$PREFIX/sbin/kresd -f 1 -q -c $(pwd)/ci/respdiff/kresd.config &>>kresd.log &

# wait until socket is receiving connections
sleep 1
