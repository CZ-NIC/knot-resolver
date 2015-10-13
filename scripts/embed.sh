#!/bin/sh
set -e
alias strip="sed -e 's/^[    ]*//g; s/[ ][ ]*/ /g; /^--/d; /^$/d'"
if command -v xxd > /dev/null 2>&1; then
	xxd -i - < $1 | strip
else
	hexdump -v -e '/1 "0x%02X, " " "' < $1 | strip
fi
exit $?
