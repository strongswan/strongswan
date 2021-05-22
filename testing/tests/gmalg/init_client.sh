
killall charon

cp swanctl/kernel-libipsec.conf /ipsec/etc/strongswan.d/charon/
cp swanctl/client.conf  /ipsec/etc/swanctl/conf.d/
/ipsec/libexec/ipsec/charon &
