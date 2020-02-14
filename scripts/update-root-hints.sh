#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o nounset -o xtrace

TEMP_FILE=/tmp/root.hints
HINTS_FILE=etc/root.hints

# download latest root hints
wget -O ${TEMP_FILE} https://www.internic.net/domain/named.root

# strip comments for diff
sed '/^;/d' ${TEMP_FILE} > ${TEMP_FILE}.clean
sed '/^;/d' ${HINTS_FILE} > ${HINTS_FILE}.clean

# check for changes
diff ${TEMP_FILE}.clean ${HINTS_FILE}.clean >/dev/null
CHANGED=$?

if [ $CHANGED -ne 0 ]; then
    # update root.hints
    mv ${TEMP_FILE} ${HINTS_FILE}
fi

# cleanup
rm -f ${TEMP_FILE} ${TEMP_FILE}.clean ${HINTS_FILE}.clean

# signal change with exit code
exit $CHANGED
