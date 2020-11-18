#!/bin/bash
# Script to create/update Knot Resolver PGP keyring
set -o errexit -o nounset

keys=(
    'B6006460B60A80E782062449E747DF1F9575A3AA'  # vladimir.cunat@nic.cz
    '4A8BA48C2AED933BD495C509A1FBA5F7EF8C4869'  # tomas.krizek@nic.cz
    '457996D019A7B7C6C2F6862A16CFB506F21D834A'  # lukas.jezek@nic.cz
)
outfile="kresd-keyblock.asc"
url="https://secure.nic.cz/files/knot-resolver/kresd-keyblock.asc"

# obtain keys from keys.openpgp.org
keyring="$(mktemp -d)"
gpg --homedir "${keyring}" -q --keyserver keys.openpgp.org --recv-keys "${keys[@]}"

# export minimal size keys with just the necessary signatures
rm -f "${outfile}"
gpg --homedir "${keyring}" -q --export --export-options export-minimal --armor --output "${outfile}" "${keys[@]}"

# display keys after import
keyring_import="$(mktemp -d)"
gpg --homedir "${keyring_import}" -q --import "${outfile}"
gpg --homedir "${keyring_import}" -k
echo "Created: ${outfile}"

# check if update of secure.nic.cz keyblock might be needed
published="$(mktemp)"
curl -sfo "${published}" "${url}"
diff -q "${outfile}" "${published}" &>/dev/null || echo "Generated keyblock differs from ${url}"
