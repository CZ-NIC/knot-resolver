#!/bin/bash
# Script to create/update Knot Resolver PGP keyring
set -o errexit -o nounset

keys=(
    'B6006460B60A80E782062449E747DF1F9575A3AA'  # vladimir.cunat@nic.cz
    '4A8BA48C2AED933BD495C509A1FBA5F7EF8C4869'  # tomas.krizek@nic.cz
    '457996D019A7B7C6C2F6862A16CFB506F21D834A'  # lukas.jezek@nic.cz
)
url="https://keys.openpgp.org/vks/v1/by-fingerprint/"
outfile="kresd-keyblock.asc"

tmpdir=$(mktemp -d)
keyring="${tmpdir}/.gnupg"

for key in "${keys[@]}"; do
    curl -sfo "${tmpdir}/${key}" "${url}${key}"
    GNUPGHOME=${keyring} gpg -q --import "${tmpdir}/${key}"
done

rm -f "${outfile}"
GNUPGHOME=${keyring} gpg -q --export --export-options export-minimal --armor --output "${outfile}"

# display keys after import
keyring2=$(mktemp -d)
GNUPGHOME=${keyring2} gpg -q --import "${outfile}"
GNUPGHOME=${keyring2} gpg -k
echo "Created: ${outfile}"
