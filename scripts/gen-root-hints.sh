#!/bin/sh

echo "/* generated root hints */"

for atype in A AAAA; do
	for n in a b c d e f g h i j k l m; do
		ip="$(kdig "$atype" "$n.root-servers.net." +dnssec +short)"
		ip_hex="$("$(dirname "$0")"/inet_pton.py "$ip")"
		echo "#define HINT_${n}_${atype} \"$ip_hex\""
	done
done

