#!/bin/sh
exec sed -e '/<failure \/>/,/<\/testcase>/s/<\(\/\?\)system-\(out\|err\)>/<\1failure>/g' \
   	-e 's/<failure \/>//g' \
	-i "$@"
