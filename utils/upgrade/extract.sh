#!/bin/sh

UPG_DIR=/tmp/kr_dev/etc/knot-resolver/.upgrade-4-to-5

# TODO only for testing, future - skip if dir exists
rm -rf ${UPG_DIR}

mkdir -p ${UPG_DIR}

for sock in kresd.socket kresd-tls.socket kresd-webmgmt.socket kresd-doh.socket ; do
    if systemctl is-enabled ${sock} 2>/dev/null | grep -qv masked ; then
        systemctl show ${sock} -p Listen > ${UPG_DIR}/${sock}
        case "$(systemctl show ${sock} -p BindIPv6Only)" in
        *ipv6-only)
            touch ${UPG_DIR}/${sock}.v6only
            ;;
        *default)
            if cat /proc/sys/net/ipv6/bindv6only | grep -q 1 ; then
                touch ${UPG_DIR}/${sock}.v6only
            fi
            ;;
        esac
    fi
done
