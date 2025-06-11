#!/usr/bin/env bash

set -e

curl --silent --fail --unix-socket /run/knot-resolver/kres-api.sock http://localhost/metrics > /dev/null

kresctl metrics > /dev/null
if [ "$?" -ne "0" ]; then
	echo "Could not get metrics in JSON format"
	exit 1
fi

kresctl metrics --prometheus > /dev/null
if [ "$?" -ne "0" ]; then
	echo "Could not get metrics in Prometheus format"
	exit 1
fi

json_count=$(kresctl metrics | grep --invert-match '{\|}' --count)
prometheus_count=$(kresctl metrics --prometheus | grep --invert-match '^#' | grep '^resolver' --count)
worker_count=$(kresctl metrics | grep --fixed-strings 'kresd:' --count)
# Prometheus additionally contains resolver_response_latency_count and resolver_metrics_loaded
if [ $(($json_count + 2 * $worker_count)) -ne $prometheus_count ]; then
	echo "JSON and Prometheus have different number of base metrics"
	exit 1
fi
