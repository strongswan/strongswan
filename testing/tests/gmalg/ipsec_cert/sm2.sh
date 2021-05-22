export LD_LIBRARY_PATH=/ipsec/lib
export PATH=/ipsec/bin:/ipsec/sbin:$PATH

pki --gen --type sm2 --outform pem > ca.key.pem
pki --self --in ca.key.pem --type sm2 --digest sm3 --dn "C=cn, O=ilove, CN=VPN CA" \
		--ca --lifetime 3650 --outform pem > ca.cert.pem

pki --gen --type sm2 --outform pem > server.key.pem
pki --pub --type sm2 --in server.key.pem --outform pem > server.pub.key.pem
pki --req --in server.key.pem --type sm2 --dn "C=cn, O=ilove, CN=VPN Server" \
		--digest sm3 --outform pem > server.req.pem

pki --issue --in server.req.pem --type pkcs10 --digest sm3 --lifetime 1200 \
		--cacert ca.cert.pem --cakey ca.key.pem --flag serverAuth \
		--flag ikeIntermediate --san="192.168.181.130" \
		--outform pem > server.cert.pem

pki --gen --type sm2 --outform pem > client.key.pem
pki --pub --in client.key.pem --type sm2 | pki --issue --digest sm3 --cacert ca.cert.pem \
		--cakey ca.key.pem --dn "C=cn, O=ilove, CN=VPN Client" \
		--outform pem > client.cert.pem
