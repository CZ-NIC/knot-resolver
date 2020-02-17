#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o nounset -o xtrace

cd "$(git rev-parse --show-toplevel)"
AUTHORS_FILE=AUTHORS
TEMP_FILE=/tmp/AUTHORS

# drop all names from the current file
sed '/^People who contributed commits to our Git repo are/q' "${AUTHORS_FILE}" > "${TEMP_FILE}"
# append all to the new file
git log --format="%aN <%aE>" | sort -u | git check-mailmap --stdin | sort -u >> "${TEMP_FILE}"

# check for changes
diff "${AUTHORS_FILE}" "${TEMP_FILE}"
CHANGED=$?

if [ $CHANGED -ne 0 ]; then
    # update
    mv "${TEMP_FILE}" "${AUTHORS_FILE}"
fi

# cleanup
rm -f ${TEMP_FILE}

# signal change with exit code
exit $CHANGED
