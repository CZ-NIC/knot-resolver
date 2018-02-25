#!/bin/bash -x

# Configure which repos to use in knot-resolver-test.yaml (vars - repos)
# Example usage: ./test-distro.sh debian9

cd "$1"
vagrant destroy &>/dev/null
vagrant up
ret=$?
vagrant destroy &>/dev/null
exit $ret

