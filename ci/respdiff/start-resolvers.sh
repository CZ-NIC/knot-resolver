# SPDX-License-Identifier: GPL-3.0-or-later

#run unbound
service unbound start && service unbound status;
# dig @localhost -p 53535

#run bind
service named start && service named status;
# dig @localhost -p 53533

#run kresd
$PREFIX/sbin/kresd -n -q -c $(pwd)/ci/respdiff/kresd.config &>kresd.log &
# dig @localhost -p 5353
