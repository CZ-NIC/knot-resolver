#!/bin/sh
set -e
alias strip="sed -e 's/^[    ]*//g; s/[ ][ ]*/ /g; /^--/d; /^$/d'"
if hash xxd 2>/dev/null; then
	xxd -i - < $1 | strip
else
	hexdump -v -e '/1 "0x%02X, " " "' < $1 | strip
fi
