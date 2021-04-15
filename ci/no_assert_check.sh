#!/bin/sh
grep '\<assert\>' $(git ls-files | grep '\.[hc]$' | grep -vE '^(contrib|bench|tests)/')
test $? -eq 1
