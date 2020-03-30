# SPDX-License-Identifier: GPL-3.0-or-later

# CA
certtool --generate-privkey > ca-key.pem
certtool --generate-self-signed --load-privkey ca-key.pem   --template ca.tmpl --outfile ca.pem

# server cert signed by CA above
certtool --generate-privkey > server-key.pem
certtool --generate-certificate --load-privkey server-key.pem   --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem   --template server.tmpl --outfile server.pem

# wrong CA - unrelated to others
certtool --generate-privkey > wrongca-key.pem
certtool --generate-self-signed --load-privkey wrongca-key.pem   --template wrongca.tmpl --outfile wrongca.pem
