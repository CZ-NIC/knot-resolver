#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o nounset -o xtrace

function spdx_originator_to_authors {
	# $1 = Person/Organization
	find -name '*.spdx' | xargs grep --no-filename "^PackageOriginator: $1: " \
		| cut -d : -f 3 | sed -e 's/^ *//' -e 's/(/</' -e 's/)/>/' | sort -u
}

cd "$(git rev-parse --show-toplevel)"
AUTHORS_FILE=AUTHORS
TEMP_FILE="$(mktemp AUTHORS.XXXXXXXXXX)"

# drop all names from the current file
sed '/^People who contributed commits to our Git repo are/q' "${AUTHORS_FILE}" > "${TEMP_FILE}"
# append to the new file
git log --format="%aN <%aE>" | sort -u | git check-mailmap --stdin | sort -u >> "${TEMP_FILE}"

echo '' >> "${TEMP_FILE}"
echo 'Knot Resolver source tree also bundles code and content published by:' >> "${TEMP_FILE}"
spdx_originator_to_authors "Person" >> "${TEMP_FILE}"
spdx_originator_to_authors "Organization" >> "${TEMP_FILE}"

echo '' >> "${TEMP_FILE}"
echo 'Thanks to everyone who knowingly or unknowingly contributed!' >> "${TEMP_FILE}"

# check for changes
diff "${AUTHORS_FILE}" "${TEMP_FILE}"
CHANGED=$?

if [ $CHANGED -ne 0 ]; then
    # update
    mv "${TEMP_FILE}" "${AUTHORS_FILE}"
fi

# cleanup
rm -f "${TEMP_FILE}"

# signal change with exit code
exit $CHANGED
