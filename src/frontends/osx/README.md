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
	./configure --prefix=/opt/local --enable-monolithic \
		--disable-shared --enable-static --disable-defaults \
		--enable-openssl --enable-kernel-pfkey --enable-kernel-pfroute \
		--enable-eap-mschapv2 --enable-eap-identity --enable-nonce \
		--enable-random --enable-pkcs1 --enable-pem --enable-socket-default \
		--enable-xauth-generic --enable-keychain --enable-charon \
		--enable-ikev1 --enable-ikev2

followed by calling make (no need to make install).

Building charon-xpc using the Xcode project yields a single binary without
any non OS X dependencies.

Both charon-xpc and the App must be code-signed to allow the installation of
the privileged helper. git-grep for "Joe Developer" to change the signing
identity.

## XPC application protocol ##

charon-xpc provides a Mach service under the name _org.strongswan.charon-xpc_.
Clients can connect to this service to control the daemon. All messages
on all connections use the following string dictionary keys/values:

* _type_: XPC message type, currently either
	* _rpc_ for a remote procedure call, expects a response
	* _event_ for application specific event messages
* _rpc_: defines the name of the RPC function to call (for _type_ = _rpc_)
* _event_: defines a name for the event (for _type_ = _event_)

Additional arguments and return values are specified by the call and can have
any type. Keys are directly attached to the message dictionary.

On the Mach service connection, the following RPC messages are currently
defined:

* string version = get_version()
	* _version_: strongSwan version of charon-xpc
* bool success = start_connection(string name, string host, string id,
								  endpoint channel)
	* _success_: TRUE if initiation started successfully
	* _name_: connection name to initiate
	* _host_: server hostname (and identity)
	* _id_: client identity to use
	* _channel_: XPC endpoint for this connection

The start_connection() RPC returns just after the initation of the call and
does not wait for the connection to establish. Nonetheless does it have a
return value to indicate if connection initiation could be triggered.

The App passes an (anonymous) XPC endpoint to start_connection(). If the call
succeeds, charon-xpc connects to this endpoint to establish a channel used for
this specific IKE connection.

On this channel, the following RPC calls are currently defined from charon-xpc
to the App:

* string password = get_password(string username)
	* _password_: user password returned
	* _username_: username to query a password for

And the following from the App to charon-xpc:

* bool success = stop_connection()
	* _success_: TRUE if termination of connection initiated

The following events are currently defined from charon-xpc to the App:

* up(): IKE_SA has been established
* down(): IKE_SA has been closed or failed to establish
* child_up(string local_ts, string remote_ts): CHILD_SA has been established
* child_down(string local_ts, string remote_ts): CHILD_SA has been closed
* log(string message): debug log message for this connection
