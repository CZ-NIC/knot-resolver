#!/bin/sh
grep '\<assert\>' -- $(git ls-files | grep '\.[hc]$' | grep -vE '^(contrib|bench|tests|.*\.test)/|^lib/kru')
test $? -eq 1
