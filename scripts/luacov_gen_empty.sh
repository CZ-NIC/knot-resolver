#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate stats file in luacov format indicating that files named on stdin
# were not processed.
#
# Normally luacov does not know about files which were not loaded so
# without this manual addition the files are missing in coverage report.

# Usage:
# $ luacov_gen_empty.sh < list_of_lua_files > luacov.empty_stats.out

set -o errexit -o nounset
IFS=$'\n'

while read FILENAME
do
	echo -e "0:${FILENAME}\n "
done
