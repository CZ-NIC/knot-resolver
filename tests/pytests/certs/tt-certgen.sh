# !/bin/sh

openssl req -config tt.conf -new -x509 -newkey rsa:2048 -nodes -keyout tt.key.pem -sha256 -out tt.cert.pem -days 20000

