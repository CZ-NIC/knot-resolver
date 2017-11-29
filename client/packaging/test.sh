#!/bin/sh
test -e client/kresc
client/kresc  # command will fail because of invalid parameters
test "$?" -eq 1  # linker error would have different exit code
