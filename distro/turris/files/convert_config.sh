#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

convert_hostname_config(){
	#convert hostname_config from option to list
	hostnames=$(uci show resolver.kresd.hostname_config)
	item_count=$(echo "$hostnames"| tr -cd "'"|wc -c)
	if [ "$item_count" -gt  "2" ] || [ "$item_count" == "0" ]; then
		echo "resolver.kresd.hostname_config was already converted to list"
	else
		echo "converting resolver.kresd.hostname_config to list"
		val=$(uci get resolver.kresd.hostname_config)
		uci delete resolver.kresd.hostname_config
		uci add_list resolver.kresd.hostname_config=$val
		uci commit resolver
	fi
}

convert_hostname_config
