#!/bin/sh
sed 's|</testcase>|</testcase>\n|g' -i "$@"
sed -e '/<failure \/>/,/<\/testcase>/s/<\(\/\?\)system-\(out\|err\)>/<\1failure>/g' \
	-e 's/<failure \/>//g' \
	-i "$@"
