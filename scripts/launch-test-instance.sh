#!/bin/sh -e
export PATH="/usr/lib/ccache:$PATH"

PORT=${1:-$((32767+$(dd if=/dev/urandom count=1 2> /dev/null | cksum | cut -d' ' -f1) % 32768))}

JOBS=$(cat /proc/cpuinfo  | grep processor | wc -l)

WORKDIR=${2:-$(mktemp -d /tmp/knot-resolver.XXXXXX)}

PREFIX=${PREFIX:-$WORKDIR} make clean

CFLAGS=${CFLAGS:-"-O2 -g3"} PREFIX=${PREFIX:-$WORKDIR} make -j ${JOBS}

PREFIX=${PREFIX:-$WORKDIR} make install

install -d -m 0700 ${WORKDIR}/run/kresd

echo "Launching Knot Resolver on port: ${PORT}"
echo "To debug, use: dig +time=60 +retry=1 -p ${PORT} @::1 <query>"

LD_LIBRARY_PATH=${WORKDIR}/lib ${WORKDIR}/sbin/kresd -a 127.0.0.1#${PORT} -a ::1#${PORT} -v -k ${ROOT_KEY:-/usr/share/dns/root.key} ${WORKDIR}/run/kresd

rm -r ${WORKDIR}
