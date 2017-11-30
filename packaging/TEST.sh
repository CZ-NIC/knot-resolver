#!/bin/bash
set -o errexit -o nounset -o xtrace

function t() {
	python3 packaging/test_pkgs_docker.py debian 9 daemon/packaging $1 --srcdir="knot-resolver-1.5.0-60-g72c7151b" > Dockerfile
	sudo docker build --rm=$2 .

}

t "" false

for f in tests/packaging tests/coverage/packaging doc/packaging scripts/packaging modules/priming/packaging modules/kmemcached/packaging modules/graphite/packaging modules/view/packaging modules/policy/packaging modules/dns64/packaging modules/ketcd/packaging modules/predict/packaging modules/stats/packaging modules/workarounds/packaging modules/renumber/packaging modules/dnstap/packaging modules/redis/packaging modules/hints/packaging modules/http/packaging modules/daf/packaging modules/version/packaging modules/ta_signal_query/packaging modules/cookies/packaging

	do t $f true
done
