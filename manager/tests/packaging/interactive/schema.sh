#!/bin/bash

set -e

kresctl schema
if [ "$?" -ne "0" ]; then
	echo "Failed to generate JSON schema with 'kresctl'"
	exit 1
fi

kresctl schema --live
if [ "$?" -ne "0" ]; then
	echo "Failed to get JSON schema from the running resolver"
	exit 1
fi
