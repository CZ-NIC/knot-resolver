#!/bin/sh -e

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

case "$1" in
    libknot) library="$(PATH="$(pkg-config libknot --variable=libdir)" command -v "$1.so")" ;;
    *) library="$(PATH="$(pwd)/lib" command -v "$1.so")"
esac

if [ -z "$library" ]; then
	echo "$1 not found.  Note: only .so platforms work currently." >&2
	exit 1
fi

GDB="gdb -quiet -symbols=$library"

grep -v '^#\|^$' | while read ident; do
	output="$(
		if [ "$2" = functions ]; then
			$GDB --ex "info functions ^$ident\$" --ex quit \
				| sed '1,/^All functions/ d; /^File .*:$/ d'
			continue
		fi
		# else types
		case "$ident" in
			struct\ *|union\ *|enum\ *)
				$GDB --ex "ptype $ident" --ex quit \
					| sed '1d; 2s/type = /\n/'
				echo ";"
				;;
			*)
				$GDB --ex "info types ^$ident\$" --ex quit \
					| sed -e '1,/^File .*:$/ d' -e '/^File .*:$/,$ d'
					# we need to stop early to remove ^^ multiple matches
				;;
		esac
	)"
	# abort on empty output
	if [ -z "$(echo "$output" | tr -d \n)" ]; then
		echo "Failed to find cdef of $ident" >&2
		exit 1
	fi
	echo "$output" | grep -v '^$'
done

exit 0
