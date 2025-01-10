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

function count_errors(){
    echo "$(journalctl -u knot-resolver.service | grep -c error)"
}

function count_reloads(){
    echo "$(journalctl -u knot-resolver.service | grep -c "TLS cert files reload triggered")"
}



# test reload without files configure
# {{

err_count=$(count_errors)
rel_count=$(count_reloads)

kresctl reload
if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -ne $rel_count ]; then
    echo "TLS cert files reload triggered when should not be."
    exit 1
fi

# }}

# configure TLS certificate files
kresctl config set -p /network/tls "$tls_certificate_conf"
if [ "$?" -ne "0" ]; then
    echo "Could not set TLS certificate files."
    exit 1
fi

# test reload on no config changes
# {{

rel_count=$(count_reloads)

kresctl config set -p /workers 2
if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "TLS cert files reload not triggered whe should be."
    exit 1
fi

# }}

# test reload on config changes
# {{

rel_count=$(count_reloads)

kresctl config set -p /workers 5
if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -ne $rel_count ]; then
    echo "TLS cert files reload triggered when should not be."
    exit 1
fi

# }}

# test reload again on no config changes
# {{

rel_count=$(count_reloads)

kresctl config set -p /workers 5
if [ $(count_errors) -ne $err_count ] || [ $(count_reloads) -eq $rel_count ]; then
    echo "TLS cert files reload not triggered whe should be."
    exit 1
fi

# }}

# reload to defaults
kresctl reload
if [ "$?" -ne "0" ]; then
    echo "The resolver reload failed."
    exit 1
fi

