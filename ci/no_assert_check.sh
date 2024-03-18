#!/bin/sh
grep '\<assert\>' -- $(git ls-files | grep '\.[hc]$' | grep -vE '^(contrib|bench|tests|daemon/rrl)/')
test $? -eq 1
