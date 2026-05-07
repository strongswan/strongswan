
arg ALPINE_TAG=3.18.4

# ------------------------------------------------------------------------
from alpine:${ALPINE_TAG} as build

run apk add --no-cache alpine-sdk gmp-dev iptables-dev openssl-dev libgcrypt-dev botan-dev
workdir /build

run apk add --no-cache autoconf automake libtool pkgconfig gettext-dev flex bison gperf
copy . .
run ./autogen.sh

copy docker/in-docker-build .
run ./in-docker-build configure
run ./in-docker-build make
run ./in-docker-build install

# ------------------------------------------------------------------------
from alpine:${ALPINE_TAG}

run apk add --no-cache iproute2 iptables gmp openssl libgcrypt botan

copy docker/entrypoint.sh /
entrypoint ["/entrypoint.sh"]

copy --from=build /target/ /
