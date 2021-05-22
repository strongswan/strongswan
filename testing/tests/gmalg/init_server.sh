
killall charon

cp swanctl/kernel-libipsec.conf /ipsec/etc/strongswan.d/charon/
cp swanctl/server.conf  /ipsec/etc/swanctl/conf.d/
/ipsec/libexec/ipsec/charon  &
