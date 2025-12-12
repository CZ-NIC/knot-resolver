#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# exit on any error
set -e

broker="localhost"
if [ -n "$1" ]
  then
    broker="$1"
fi

topic="knot-resolver"
if [ -n "$2" ]
  then
    topic="$2"
fi

group_id="dns-group1"
if [ -n "$3" ]
  then
    group_id="$3"
fi

# send small list
python tests/kafka/send_file.py $broker $topic $group_id tests/kafka/smalllist.rpz

# send giga list
python tests/kafka/send_file.py $broker $topic $group_id tests/kafka/gigalist.rpz

# send new configuration
python tests/kafka/send_file.py $broker $topic $group_id tests/kafka/config.json

# compare files
sleep 10
diff .install_dev/var/lib/knot-resolver/smalllist.rpz tests/kafka/smalllist.rpz
diff .install_dev/var/lib/knot-resolver/gigalist.rpz tests/kafka/gigalist.rpz
diff .install_dev/var/lib/knot-resolver/config.json tests/kafka/config.json
