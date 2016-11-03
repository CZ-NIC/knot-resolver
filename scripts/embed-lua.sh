#!/bin/sh
set -e
# clean unnecessary stuff from the lua file
alias strip="sed -e 's/^[\t ]*//g; s/  */ /g; /^--/d; /^$/d'"
if command -v xxd > /dev/null 2>&1; then
	strip < "$1" | xxd -i -
else
	strip < "$1" | hexdump -v -e '/1 "0x%02X, " " "'
fi
exit $?
