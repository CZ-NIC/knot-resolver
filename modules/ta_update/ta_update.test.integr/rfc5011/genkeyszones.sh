#!/usr/bin/bash

# First, generate DNSSEC keys with timers set to simulate 2017 KSK roll-over.
# Second, fake system time to pretend that we are at the beginning on time slots
# used during 2017 and sign our fake root zone.

# Depends on libfaketime + dnssec-keygen and dnssec-signzone from BIND 9.11.

# Output: Bunch of DNSSEC keys + several versions of signed root zone.

set -o nounset -o errexit -o xtrace

GEN="dnssec-keygen 	-r /dev/urandom	-K keys/ -a RSASHA256 -b 2048 	-L 21d"

function sign {
	OUTFILE="$(echo "$1" | sed 's/[- :]//g').db"
	TZ=UTC \
	LD_PRELOAD="/usr/lib64/faketime/libfaketimeMT.so.1" \
	FAKETIME="$1" \
	dnssec-signzone	\
	-r /dev/urandom \
	-K keys/ \
	-o . \
	-S \
	-T 21d \
	-s now \
	-e +14d \
	-X +21d \
	-O full \
	-f "${OUTFILE}" \
	unsigned.db

	# DS for the very first KSK
	test ! -f keys/ds && dnssec-dsfromkey -2 -f "${OUTFILE}" . > keys/ds || : initial DS RR already exists
}

rm -f 20*.db
rm -f keys/K*
rm -f keys/ds
mkdir -p keys/

# old KSK
${GEN} -f KSK -P 20100715000000 -A 20100715000000 -I 20171011000000 -R 20180111000000 -D 20180322000000 .
# new KSK
${GEN} -f KSK -P 20170711000000 -A 20171011000000 .

# ZSK before roll-over: 2017-Q2
${GEN} -P 20170320000000 -A 20170401000000 -I 20170701000000 -D 20170711000000 .
# ZSK-q1: 2017-Q3
${GEN} -P 20170621000000 -A 20170701000000 -I 20171001000000 -D 20171011000000 .
# ZSK-q2: 2017-Q4
${GEN} -P 20170919000000 -A 20171001000000 -I 20180101000000 -D 20180111000000 .
# ZSK-q3: 2018-Q1
${GEN} -P 20171220000000 -A 20180101000000 -I 20180401000000 -D 20180411000000 .
# ZSK: 2018-Q2
${GEN} -P 20180322000000 -A 20180401000000 .


# hopefully slots according to
# https://www.icann.org/en/system/files/files/ksk-rollover-operational-implementation-plan-22jul16-en.pdf
# https://data.iana.org/ksk-ceremony/29/KC29_Script_Annotated.pdf
sign "2017-07-01 00:00:00"  # 2017 Q3 slot 1
sign "2017-07-11 00:00:00"  # 2017 Q3 slot 2
sign "2017-07-21 00:00:00"  # 2017 Q3 slot 3
sign "2017-07-31 00:00:00"  # 2017 Q3 slot 4
sign "2017-08-10 00:00:00"  # 2017 Q3 slot 5
sign "2017-08-20 00:00:00"  # 2017 Q3 slot 6
sign "2017-08-30 00:00:00"  # 2017 Q3 slot 7
sign "2017-09-09 00:00:00"  # 2017 Q3 slot 8
sign "2017-09-19 00:00:00"  # 2017 Q3 slot 9

sign "2017-10-01 00:00:00"  # 2017 Q4 slot 1
sign "2017-10-11 00:00:00"  # 2017 Q4 slot 2
sign "2017-10-21 00:00:00"  # 2017 Q4 slot 3
sign "2017-10-31 00:00:00"  # 2017 Q4 slot 4
sign "2017-11-10 00:00:00"  # 2017 Q4 slot 5
sign "2017-11-20 00:00:00"  # 2017 Q4 slot 6
sign "2017-11-30 00:00:00"  # 2017 Q4 slot 7
sign "2017-12-10 00:00:00"  # 2017 Q4 slot 8
sign "2017-12-20 00:00:00"  # 2017 Q4 slot 9

# 2018-01-01 00:00:00  # 2018 Q1 slot 1
# 2018-01-11 00:00:00  # 2018 Q1 slot 2
# 2018-01-21 00:00:00  # 2018 Q1 slot 3
# 2018-01-31 00:00:00  # 2018 Q1 slot 4
# 2018-02-10 00:00:00  # 2018 Q1 slot 5
# 2018-02-20 00:00:00  # 2018 Q1 slot 6
# 2018-03-02 00:00:00  # 2018 Q1 slot 7
# 2018-03-12 00:00:00  # 2018 Q1 slot 8
# 2018-03-22 00:00:00  # 2018 Q1 slot 9
