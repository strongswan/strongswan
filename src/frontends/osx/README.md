# strongSwan OS X App #

## Introduction ##

The strongSwan OS X App consists of two components:

* A frontend to configure and control connections
* A privileged helper daemon, controlled using XPC, called charon-xpc

The privileged helper daemon gets installed automatically using SMJobBless
functionality on its first use, and gets started automatically by Launchd when
needed.

charon-xpc is a special build linking statically against strongSwan components.

## Building strongSwan ##

strongSwan on OS X requires the libvstr library. The simplest way to install
it is using MacPorts. It gets statically linked to charon-xpc, hence it is not
needed to run the built App.

Before building the Xcode project, the strongSwan base tree must be built using
a monolithic and static build. This can be achieved on OS X by using:

LDFLAGS="-all_load" \
CFLAGS="-I/usr/include -DOPENSSL_NO_CMS -O2 -Wall -Wno-format -Wno-pointer-sign" \
./configure --prefix=/opt/local --disable-defaults --enable-openssl \
  --enable-kernel-pfkey --enable-kernel-pfroute --enable-eap-mschapv2 \
  --enable-eap-identity --enable-monolithic --enable-nonce --enable-random \
  --enable-pkcs1 --enable-pem --enable-socket-default --enable-xauth-generic \
  --enable-ikev1 --enable-ikev2 --enable-charon --disable-shared --enable-static

followed by calling make (no need to make install).

Building charon-xpc using the Xcode project yields a single binary without
any non OS X dependencies.

Both charon-xpc and the App must be code-signed to allow the installation of
the privileged helper. git-grep for "Joe Developer" to change the signing
identity.