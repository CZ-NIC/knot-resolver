#!/usr/bin/env bash

set -e

curl --silent --fail --unix-socket /run/knot-resolver/kres-api.sock http://localhost/metrics > /dev/null

kresctl metrics
if [ "$?" -ne "0" ]; then
	echo "Could not get metrics in JSON format"
	exit 1
fi

kresctl metrics --prometheus
if [ "$?" -ne "0" ]; then
	echo "Could not get metrics in Prometheus format"
	exit 1
fi
