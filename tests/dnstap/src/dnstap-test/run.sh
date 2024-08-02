#!/usr/bin/env bash
set -e
KRESD_CMD=$1
MESON_BUILD_ROOT=$(pwd)
mkdir -p tests/dnstap
export GOPATH=$MESON_BUILD_ROOT/tests/dnstap
echo "$GOPATH"
cd "$(dirname $0)"
DNSTAP_TEST=dnstap-test

go mod tidy

type -P go >/dev/null || exit 77
echo "Building the dnstap test and its dependencies..."
# some packages may be missing on the system right now
go get .

DTAP_DIR="$GOPATH/src"
DTAP="$DTAP_DIR/$DNSTAP_TEST"
mkdir -p "$DTAP_DIR"
rm -f $DTAP && ln -s $(realpath ..)/$DNSTAP_TEST $DTAP
go install .


CONFIG=$(realpath ./config)
ZONES="fake1.localdomain,fake2.localdomain,fake3.localdomain"
TIMEOUT=60s
GRACE=5s
cd $MESON_BUILD_ROOT/tests/dnstap # don't leave stuff like *.mdb in ./.
$GOPATH/bin/$DNSTAP_TEST -c $CONFIG -cmd $KRESD_CMD -q $ZONES -t $TIMEOUT -g $GRACE -d

