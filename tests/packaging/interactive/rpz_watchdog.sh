#!/usr/bin/env bash

set -e

gitroot=$(git rev-parse --show-toplevel)
rpz_file=$gitroot/example.rpz

rpz_example=$(cat <<EOF
\$ORIGIN RPZ.EXAMPLE.ORG.
ok.example.com                    CNAME rpz-passthru.
EOF
)
# create example RPZ
echo "$rpz_example" >> $rpz_file

rpz_conf=$(cat <<EOF
local-data:
  rpz:
    - file: $rpz_file
      watchdog: false
EOF
)
# add RPZ to config
echo "$rpz_conf" >> /etc/knot-resolver/config.yaml

function count_errors(){
    echo "$(journalctl -u knot-resolver.service | grep -c error)"
}

function count_reloads(){
    echo "$(journalctl -u knot-resolver.service | grep -c "Renewing configuration has finished")"
}

# test that RPZ watchdog
# {{

err_count=$(count_errors)
rel_count=$(count_reloads)

# reload config with RPZ configured without watchdog turned on
kresctl reload
sleep 1
if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -ne $rel_count ]; then
    echo "RPZ file watchdog is running (should not) or other errors occurred."
    exit 1
fi

# configure RPZ file and turn on watchdog
kresctl config set -p /local-data/rpz/0/watchdog true
sleep 1
if [ "$?" -ne "0" ]; then
    echo "Could not turn on RPZ file watchdog."
    exit 1
fi

# }}

# test RPZ modification
# {{

# modify RPZ file, it will trigger reload
rel_count=$(count_reloads)
echo "32.1.2.0.192.rpz-client-ip        CNAME rpz-passthru." >> $rpz_file

# wait for files reload to finish
sleep 10

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload modified RPZ file."
    exit 1
fi

# }}

# test replacement
# {{

rel_count=$(count_reloads)

# copy RPZ file
cp $rpz_file $rpz_file.new

# edit new files
echo "48.zz.101.db8.2001.rpz-client-ip  CNAME rpz-passthru." >> $rpz_file.new

# replace files
cp -f $rpz_file.new $rpz_file

# wait for files reload to finish
sleep 10

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload replaced RPZ file."
    exit 1
fi

# }}

# test recovery from deletion and creation
# {{

rel_count=$(count_reloads)

# backup rpz file
cp $rpz_file $rpz_file.backup

# delete RPZ file
rm $rpz_file

# create cert files
cp -f $rpz_file.backup $rpz_file

# wait for files reload to finish
sleep 10

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload created RPZ file."
    exit 1
fi

# }}
