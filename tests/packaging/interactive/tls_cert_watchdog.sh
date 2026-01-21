#!/usr/bin/env bash

set -e

gitroot=$(git rev-parse --show-toplevel)
cert_file=$gitroot/modules/http/test_tls/test.crt
key_file=$gitroot/modules/http/test_tls/test.key

tls_certificate_conf=$(cat <<EOF
{
    "cert-file": "$cert_file",
    "key-file": "$key_file"
}
EOF
)

# configure TLS certificate files
kresctl config set -p /network/tls "$tls_certificate_conf"
if [ "$?" -ne "0" ]; then
    echo "Could not set TLS certificate files."
    exit 1
fi

function count_errors(){
    echo "$(journalctl -u knot-resolver.service | grep -c error)"
}

function count_reloads(){
    echo "$(journalctl -u knot-resolver.service | grep -c "to reload watched files has finished")"
}

# test that files watchdog is turned off
# {{

err_count=$(count_errors)
rel_count=$(count_reloads)
sleep 6

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -ne $rel_count ]; then
    echo "TLS certificate files watchdog is running (should not) or other errors occurred."
    exit 1
fi

# }}

# configure TLS certificate files and turn on watchdog
kresctl config set -p /network/tls/watchdog true
if [ "$?" -ne "0" ]; then
    echo "Could not turn on TLS certificate files watchdog."
    exit 1
fi

# test modification
# {{

# modify certificate files with '-', it will trigger reload
rel_count=$(count_reloads)
echo "-----------" >> $cert_file
echo "-----------" >> $key_file

# wait for files reload to finish
sleep 6

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload modified TLS certificate files."
    exit 1
fi

# }}

# test replacement
# {{

rel_count=$(count_reloads)

# copy cert files
cp $cert_file test.crt.new
cp $key_file test.key.new

# edit new files
echo "-----------" >> test.crt.new
echo "-----------" >> test.key.new

# replace files
mv -f test.crt.new $cert_file
mv -f test.key.new $key_file

# wait for files reload to finish
sleep 6

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload replaced TLS certificate files."
    exit 1
fi

# }}

# test recovery from deletion and creation
# {{

rel_count=$(count_reloads)

# backup cert files
cp $cert_file test.crt.backup
cp $key_file test.key.backup

# delete cert files
rm $cert_file $key_file

# create cert files
mv test.crt.backup $cert_file
mv test.key.backup $key_file

# wait for files reload to finish
sleep 6

if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "Could not reload created TLS certificate files."
    exit 1
fi

# }}
