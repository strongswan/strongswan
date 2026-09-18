arg SWANIMAGE=strongswan

from alpine:3.18.4 as testing

arg NET_PREFIX=192.168.0.

copy . /testing/
run find /testing -type f -exec sed -i \
 -e "s,192\.168\.0\.,${NET_PREFIX}," \
 {} +

from ${SWANIMAGE}

run apk add --no-cache bash

run find /etc/ipsec.* -type f -exec rm {} +

arg HOST=moon

copy --from=testing /testing/hosts/default/ /
copy --from=testing /testing/hosts/${HOST}/ /

arg TEST=ikev2/rw-psk-ipv4

copy --from=testing /testing/tests/${TEST}/hosts/${HOST}/ /

