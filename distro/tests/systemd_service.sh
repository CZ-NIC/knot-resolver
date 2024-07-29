#!/bin/bash

# fail fast
set -e

# check for root
if test "$(id -u)" -ne 0; then
	echo "Must be run as root"
	exit 1
fi

# We will be starting a systemd service, but another tests might do the same
# so this makes sure there is nothing left after we exit
trap "systemctl stop kresd@1.service" EXIT


if ! systemctl start kresd@1.service; then
	echo
	echo "Failed to start service, here is its status:"
	systemctl status kresd@1.service || true
	echo
	echo "kresd@1.service:"
	systemctl cat kresd@1.service || true
	echo
	echo "Checking service user using \`id knot-resolver\`:"
	id knot-resolver
	exit 1
else
	set +e

	# check that the resolvers are actually running
	kdig @127.0.0.1 +edns nic.cz | tee /dev/stderr | grep -qi 'status: NOERROR'
	if [ "$?" -ne "0" ]; then
		echo "Could not 'kdig' the resolver - is it running?"
		exit 1
	fi
fi
