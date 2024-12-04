#!/usr/bin/env bash

# clear full cache
kresctl cache clear > /dev/null
if [ "$?" -ne "0" ]; then
	echo "Could not clear full cache"
	exit 1
fi

# clear just example.com. AAAA record, get JSON output
kresctl cache clear --json --exact-name --rr-type AAAA example.com. | python3 -m json.tool > /dev/null
if [ "$?" -ne "0" ]; then
	echo "Could not clear example.com. AAAA record or output is not a valid JSON"
	exit 1
fi
