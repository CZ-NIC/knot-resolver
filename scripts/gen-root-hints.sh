#!/bin/sh -e

echo "/* generated root hints */"

for atype in A AAAA; do
	# address length when using \xNN escapes
	if [ "$atype" = A ]; then
		alen=16
	elif [ "$atype" = AAAA ]; then
		alen=64
	else
		exit 1
	fi

	for n in a b c d e f g h i j k l m; do
		ip="$(kdig "$atype" "$n.root-servers.net." +dnssec +short)"
		ip_hex="$("$(dirname "$0")"/inet_pton.py "$ip")"
		[ "$(printf "%s" "$ip_hex" | wc -c)" = "$alen" ] || exit 1
		echo "#define HINT_${n}_${atype} \"$ip_hex\""
	done
done

