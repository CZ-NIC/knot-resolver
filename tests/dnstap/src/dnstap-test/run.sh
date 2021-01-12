#!/bin/bash
set -e
KRESD_CMD=$1
MESON_BUILD_ROOT=$(pwd)
export GOPATH=$MESON_BUILD_ROOT/tests/dnstap
cd "$(dirname $0)"
DNSTAP_TEST=dnstap-test

type -P go >/dev/null || exit 77
echo "Building the dnstap tests and its dependencies..."
# some packages may be missing on the system right now
go get github.com/{FiloSottile/gvt,cloudflare/dns,dnstap/golang-dnstap}
DTAP=$GOPATH/src/$DNSTAP_TEST
rm -f $DTAP && ln -s $(realpath ..)/$DNSTAP_TEST $DTAP
go install $DNSTAP_TEST


CONFIG=./config
ZONES="fake1.localdomain,fake2.localdomain,fake3.localdomain"
TIMEOUT=60s
$GOPATH/bin/$DNSTAP_TEST -c $CONFIG -cmd $KRESD_CMD -q $ZONES -t $TIMEOUT -d

