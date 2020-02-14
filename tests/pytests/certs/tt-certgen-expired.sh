# !/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

if [ ! -d ./demoCA ]; then
  mkdir ./demoCA
fi
if [ ! -d ./demoCA/newcerts ]; then
  mkdir ./demoCA/newcerts
fi
touch ./demoCA/index.txt
touch ./demoCA/index.txt.attr
if [ ! -f ./demoCA/serial ]; then
  echo 01 > ./demoCA/serial
fi

openssl genrsa -out tt-expired.key.pem 2048
openssl req -config tt.conf -new -key tt-expired.key.pem -out tt-expired.csr.pem
openssl ca -config tt.conf -selfsign -keyfile tt-expired.key.pem -out tt-expired.cert.pem -in tt-expired.csr.pem -startdate 19700101000000Z -enddate 19700101000000Z

