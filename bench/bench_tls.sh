#!/bin/sh

# This script benchmarks DNS-over-TLS for Knot Resolver.
# It uses getdns_query/stubby (part of the getdns-utils package) as client.

NUM_TESTS=1000
ADDRESS=127.0.0.1
PORT=853 # kresd needs to run as root
WORKERS=1

BENCH_CONN=true
BENCH_MSG=true

# Abort when dependencies are not met
require()
{
    command -v $1 >/dev/null 2>&1 || { echo >&2 "Benchmarking requires $1 to be available."; exit 1; }
}
require bc
require getdns_query
require pidof
require seq
require sudo

bench_conn()
{
    for i in $(seq $NUM_TESTS); do
        getdns_query @${ADDRESS}:${PORT} -s -m -q -x -l LT a.root-servers.net. A >/dev/null
    done
}

bench_msg()
{
    # Assumes that $queryfile is set externally
    # -a/-B for asynchronous/batch
    getdns_query @${ADDRESS}:${PORT} -a -s -B -F "$queryfile" -m -q -x -l LT >/dev/null ;
}

do_bench()
{
    # Expects a callback with the actual DNS query client as first parameter
    before=$(date +%s.%N)
    $1
    after=$(date +%s.%N)
    duration=$(echo $after-$before | bc)
    printf "This took\t%0f s.\n" "$duration"
}

# Detect wheter Knot Resolver is already running
# If not, start instance
KRESD_PID=$(pidof kresd)
KRESD_TOKILL=false

if [ ! "$KRESD_PID" ]; then
    # Start knot resolver and remember to shut it down in the end
    sudo sh -c "LD_LIBRARY_PATH=lib daemon/kresd -t $ADDRESS@$PORT -f $WORKERS -q >/dev/null &"

    sleep .5

    KRESD_PID=$(pidof kresd)
    KRESD_TOKILL=true

    if [ ! "$KRESD_PID" ]; then
        echo "Failed to start Knot Resolver."
        exit 1
    fi
fi


if [ "$BENCH_CONN" = true ]; then
    echo "Testing connections..."
    echo "Do $NUM_TESTS TCP+TLS handshakes and short A queries."
    do_bench bench_conn
fi

if [ "$BENCH_MSG" = true ]; then
    queryfile=$(mktemp)
    for i in $(seq $NUM_TESTS); do
        echo ". NS" >> "$queryfile"
    done

    echo "Testing messages..."
    echo "Do a single TCP+TLS handshake and $NUM_TESTS batched asynchronous longer NS queries."
    do_bench bench_msg

    rm -f "$queryfile"
fi

if [ "$KRESD_TOKILL" = true ]; then
    # Cleanup
    sudo sh -c "kill -9 $KRESD_PID"
fi
