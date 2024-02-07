#!/bin/bash

# clear full cache
kresctl cache clear
if [ "$?" -ne "0" ]; then
	echo "Could not clear full cache"
	exit 1
fi

# clear just example.com. AAAA record
kresctl cache clear --exact-name --rr-type AAAA example.com.
if [ "$?" -ne "0" ]; then
	echo "Could not clear example.com. AAAA record"
	exit 1
fi
