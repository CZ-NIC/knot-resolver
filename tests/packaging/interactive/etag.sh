#!/bin/bash

set -e

socket_opt="--unix-socket /var/run/knot-resolver/manager.sock"

echo "  etag"
etag="$(curl --silent $socket_opt --fail http://localhost:5000/v1/config -o /dev/null -v 2>&1 | grep ETag | sed 's/< ETag: //;s/\s//')"
echo "  etag OK"

echo "  status"
status=$(curl --silent $socket_opt --fail  http://localhost:5000/v1/config --header "If-None-Match: $etag" -w "%{http_code}" -o /dev/null)
test "$status" -eq 304
echo "  status OK"
