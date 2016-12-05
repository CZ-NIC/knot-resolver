#!/bin/sh
set -e
# Clean unnecessary stuff from the lua file; note the significant tabulator.
alias strip="sed -e 's/^[	 ]*//g; s/  */ /g; /^--/d; /^$/d'"
if command -v xxd > /dev/null 2>&1; then
	strip < "$1" | xxd -i -
else
	strip < "$1" | hexdump -v -e '/1 "0x%02X, " " "'
fi
exit $?
