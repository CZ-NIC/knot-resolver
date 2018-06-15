#!/bin/bash
set -o pipefail -o errexit

if [ "$2" != types ] && [ "$2" != functions ]; then
	echo "Usage: $0 libkres (types|functions)" >&2
	echo "    and input identifiers, one per line." >&2
	echo "    You need debug symbols in the library." >&2
	exit 1
fi

if ! command -v gdb >/dev/null; then
	echo "Failed to find gdb" >&2
	exit 1
fi

if ! command -v sed >/dev/null; then
	echo "Failed to find GNU sed" >&2
	exit 1
fi

if ! sed --version | head -1 | grep -q "GNU sed"; then
	echo "GNU sed required to run this script" >&2
fi

# be very precise with the directories for libraries to not pick wrong library
case "$1" in
	libknot) library="$(PATH="$(pkg-config libknot --variable=libdir)" command -v "$1.so")" ;;
	libzscanner) library="$(PATH="$(pkg-config libzscanner --variable=libdir)" command -v "$1.so")" ;;
	*) library="$(PATH="$(pwd)/lib" command -v "$1.so")"
esac

if [ -z "$library" ]; then
	echo "$1 not found.  Note: only .so platforms work currently." >&2
	exit 1
fi

GDB="gdb -n -quiet -batch -symbols=$library"

grep -v '^#\|^$' | while read -r ident; do
	if [ "$2" = functions ]; then
		output="$($GDB -iex "set width unlimited" --ex "info functions ^$ident\$" \
				| sed '0,/^All functions/ d; /^File .*:$/ d')"
	else # types
		case "$ident" in
			struct\ *|union\ *|enum\ *)
				output="$($GDB -iex "set width unlimited" --ex "ptype $ident" \
						| sed '0,/^type = /s/^type = /\n/; $ s/$/;/')"
				;;
			*)
				output="$($GDB -iex "set width unlimited" --ex "info types ^$ident\$" \
						| sed -e '0,/^File .*:$/ d' -e '/^File .*:$/,$ d')"
						# we need to stop early to remove ^^ multiple matches
				;;
		esac
	fi

	# abort on empty output
	if [ -z "$(echo "$output" | tr -d "\n;")" ]; then
		echo "Failed to find cdef of $ident" >&2
		exit 1
	fi
	echo "$output" | grep -v '^$'
done

exit 0
