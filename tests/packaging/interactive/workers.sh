#!/usr/bin/env bash

expected_workers="5"

kresctl config set -p /workers "$expected_workers"
if [ "$?" -ne "0" ]; then
	echo "Could not configure $expected_workers workers"
	exit 1
fi

actual_processes="$(pidof kresd | wc -w)"
if [ "$actual_processes" -ne "$expected_workers" ]; then
	echo "Incorrect number of workers"
	echo "(actual) != (expected)"
	echo "$actual_processes != $expected_workers"
	exit 1
fi
