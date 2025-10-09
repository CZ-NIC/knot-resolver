#!/usr/bin/env bash

set -e

function count_errors(){
    echo "$(journalctl -u knot-resolver.service | grep -c error)"
}

function count_apply(){
    echo "$(journalctl -u knot-resolver.service | grep -c "Config applied successfully to all workers")"
}

err_count=$(count_errors)
rel_count=$(count_apply)

curl -X POST --unix-socket /run/knot-resolver/kres-api.sock http://api/renew
sleep 6
if [ $(count_errors) -ne $err_count ] || [ $(count_apply) -ne $rel_count ]; then
    echo "Failed to renew."
    exit 1
fi

curl -X POST --unix-socket /run/knot-resolver/kres-api.sock http://api/renew/force
sleep 6
if [ $(count_errors) -ne $err_count ] || [ $(count_apply) -eq $rel_count ]; then
    echo "Failed to force a renew."
    exit 1
fi
