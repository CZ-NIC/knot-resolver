#!/bin/bash

set -e

curl --silent --fail --unix-socket /var/run/knot-resolver/manager.sock http://localhost/metrics > /dev/null
