#!/bin/bash
set -e
KRESD_CMD=$1
MESON_BUILD_ROOT=$(pwd)
mkdir -p tests/dnstap
export GOPATH=$MESON_BUILD_ROOT/tests/dnstap
cd "$(dirname $0)"
DNSTAP_TEST=dnstap-test

if [ -z "$GITLAB_CI" ]; then
	type -P go >/dev/null || exit 77
	echo "Building the dnstap test and its dependencies..."
	# some packages may be missing on the system right now
	go get github.com/{FiloSottile/gvt,cloudflare/dns,dnstap/golang-dnstap}
else
	# In CI we've prebuilt dependencies into the default GOPATH.
	# We're in a scratch container, so we just add the dnstap test inside.
	export GOPATH=/root/go
fi
DTAP=$GOPATH/src/$DNSTAP_TEST
rm -f $DTAP && ln -s $(realpath ..)/$DNSTAP_TEST $DTAP
go install $DNSTAP_TEST


CONFIG=$(realpath ./config)
ZONES="fake1.localdomain,fake2.localdomain,fake3.localdomain"
TIMEOUT=60s
GRACE=5s
cd $MESON_BUILD_ROOT/tests/dnstap # don't leave stuff like *.mdb in ./.
$GOPATH/bin/$DNSTAP_TEST -c $CONFIG -cmd $KRESD_CMD -q $ZONES -t $TIMEOUT -g $GRACE -d

