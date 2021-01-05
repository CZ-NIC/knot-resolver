#!/bin/sh
export GOPATH=$(realpath tests/dnstap)
DNSTAP_TEST=dnstap-test
DNSTAP_PATH=$(realpath ../tests/dnstap/src/$DNSTAP_TEST)
CONFIG=$DNSTAP_PATH/config
CMD=$1
ZONES="fake1.localdomain,fake2.localdomain,fake3.localdomain"
TIMEOUT=60s

type go || exit 77
# some packages may be missing on the system right now
go get github.com/{FiloSottile/gvt,cloudflare/dns,dnstap/golang-dnstap}
(cd tests/dnstap/src && rm -f $DNSTAP_TEST && ln -s $DNSTAP_PATH .)
go install $DNSTAP_TEST
(cd tests/dnstap && $GOPATH/bin/$DNSTAP_TEST -c $CONFIG -cmd $CMD -q $ZONES -t $TIMEOUT -d)

