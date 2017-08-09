#run unbound
service unbound start && service unbound status;
# dig @localhost -p 53535

#run bind
service bind9 start && service bind9 status;
# dig @localhost -p 53533

#run kresd
LD_LIBRARY_PATH=$PREFIX/lib $PREFIX/sbin/kresd -f 1 -q -c $(pwd)/ci/respdiff/kresd.config &
# dig @localhost -p 5353
