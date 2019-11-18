#!/bin/sh
test -e /usr/sbin/kresc
/usr/sbin/kresc  # command will fail because of invalid parameters
test "$?" -eq 1  # linker error would have different exit code
