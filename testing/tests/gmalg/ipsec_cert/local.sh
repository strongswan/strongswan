export LD_LIBRARY_PATH=/ipsec/lib
export PATH=/ipsec/bin:/ipsec/sbin:$PATH

cp ca.cert.pem         /ipsec/etc/swanctl/x509ca
cp server.cert.pem     /ipsec/etc/swanctl/x509
cp server.key.pem      /ipsec/etc/swanctl/private
cp client.cert.pem     /ipsec/etc/swanctl/x509
cp client.key.pem      /ipsec/etc/swanctl/private
