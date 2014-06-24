                 ----------------------------
                  strongSwan - Configuration
                 ----------------------------


Contents
--------

   1. Overview
   2. Quickstart
    2.1 Site-to-Site case
    2.2 Host-to-Host case
    2.3 Roadwarrior case
    2.4 Roadwarrior case with virtual IP
   3. Generating X.509 certificates and CRLs
    3.1 Generating a CA certificate
    3.2 Generating a host or user certificate
    3.3 Generating a CRL
    3.4 Revoking a certificate
   4. Configuring the connections - ipsec.conf
    4.1 Configuring my side
    4.2 Multiple certificates
    4.3 Configuring the peer side using CA certificates
    4.4 Handling Virtual IPs and wildcard subnets
    4.5 Protocol and port selectors
    4.6 IPsec policies based on wildcards
    4.7 IPsec policies based on CA certificates
   5. Configuring certificates and CRLs
    5.1 Installing CA certificates
    5.2 Installing optional Certificate Revocation Lists (CRLs)
    5.3 Dynamic update of certificates and CRLs
    5.4 Local caching of CRLs
    5.5 Online Certificate Status Protocol (OCSP)
    5.6 CRL policy
    5.7 Configuring the peer side using locally stored certificates
   6. Configuring the private keys - ipsec.secrets
    6.1 Loading private key files in PKCS#1 format
    6.2 Entering passphrases interactively
    6.3 Multiple private keys
   7. Configuring CA properties - ipsec.conf
   8. Monitoring functions
   9. Firewall support functions
       9.1 Environment variables in the updown script
       9.2 Automatic insertion and deletion of iptables firewall rules


1. Overview
   --------

strongSwan is an OpenSource IPsec solution for Unix based operating systems.

This document is just a short introduction, for more detailed information
consult the manual pages and our wiki:

    http://wiki.strongswan.org


2. Quickstart
   ----------

In the following examples we assume for reasons of clarity that left designates
the local host and that right is the remote host.  Certificates for users,
hosts and gateways are issued by a fictitious strongSwan CA.  How to generate
private keys and certificates using OpenSSL or the strongSwan PKI tool will be
explained in section 3.  The CA certificate "strongswanCert.pem" must be present
on all VPN end points in order to be able to authenticate the peers.


2.1 Site-to-site case
    -----------------

In this scenario two security gateways moon and sun will connect the
two subnets moon-net and sun-net with each other through a VPN tunnel
set up between the two gateways:

    10.1.0.0/16 -- | 192.168.0.1 | === | 192.168.0.2 | -- 10.2.0.0/16
      moon-net          moon                 sun           sun-net

Configuration on gateway moon:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/moonCert.pem

    /etc/ipsec.secrets:

        : RSA moonKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn net-net
            leftsubnet=10.1.0.0/16
            leftcert=moonCert.pem
            right=192.168.0.2
            rightsubnet=10.2.0.0/16
            rightid="C=CH, O=strongSwan, CN=sun.strongswan.org"
            auto=start

Configuration on gateway sun:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/sunCert.pem

    /etc/ipsec.secrets:

        : RSA sunKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn net-net
            leftsubnet=10.2.0.0/16
            leftcert=sunCert.pem
            right=192.168.0.1
            rightsubnet=10.1.0.0/16
            rightid="C=CH, O=strongSwan, CN=moon.strongswan.org"
            auto=start


2.2 Host-to-host case
    -----------------

This is a setup between two single hosts which don't have a subnet behind
them.  Although IPsec transport mode would be sufficient for host-to-host
connections we will use the default IPsec tunnel mode.

    | 192.168.0.1 | === | 192.168.0.2 |
         moon                sun

Configuration on host moon:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/moonCert.pem

    /etc/ipsec.secrets:

        : RSA moonKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn host-host
            leftcert=moonCert.pem
            right=192.168.0.2
            rightid="C=CH, O=strongSwan, CN=sun.strongswan.org"
            auto=start

Configuration on host sun:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/sunCert.pem

    /etc/ipsec.secrets:

        : RSA sunKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn host-host
            leftcert=sunCert.pem
            right=192.168.0.1
            rightid="C=CH, O=strongSwan, CN=moon.strongswan.org"
            auto=start


2.3 Roadwarrior case
    ----------------

This is a very common case where a strongSwan gateway serves an arbitrary
number of remote VPN clients usually having dynamic IP addresses.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x |
      moon-net          moon              carol

Configuration on gateway moon:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/moonCert.pem

    /etc/ipsec.secrets:

        : RSA moonKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn rw
            leftsubnet=10.1.0.0/16
            leftcert=moonCert.pem
            right=%any
            auto=add

Configuration on roadwarrior carol:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/carolCert.pem

    /etc/ipsec.secrets:

        : RSA carolKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn home
            leftcert=carolCert.pem
            right=192.168.0.1
            rightsubnet=10.1.0.0/16
            rightid="C=CH, O=strongSwan, CN=moon.strongswan.org"
            auto=start


2.6 Roadwarrior case with virtual IP
    --------------------------------

Roadwarriors usually have dynamic IP addresses assigned by the ISP they are
currently attached to.  In order to simplify the routing from moon-net back
to the remote access client carol it would be desirable if the roadwarrior had
an inner IP address chosen from a pre-assigned pool.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x | -- 10.3.0.1
      moon-net          moon              carol       virtual IP

In our example the virtual IP address is chosen from the address pool
10.3.0.0/16 which can be configured by adding the parameter

    rightsourceip=10.3.0.0/16

to the gateway's ipsec.conf.  To request an IP address from this pool a
roadwarrior can use IKEv1 mode config or IKEv2 configuration payloads.
The configuration for both is the same

    leftsourceip=%config

Configuration on gateway moon:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/moonCert.pem

    /etc/ipsec.secrets:

        : RSA moonKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn rw
            leftsubnet=10.1.0.0/16
            leftcert=moonCert.pem
            right=%any
            rightsourceip=10.3.0.0/16
            auto=add

Configuration on roadwarrior carol:

    /etc/ipsec.d/cacerts/strongswanCert.pem

    /etc/ipsec.d/certs/carolCert.pem

    /etc/ipsec.secrets:

        : RSA carolKey.pem "<optional passphrase>"

    /etc/ipsec.conf:

        conn home
            leftsourceip=%config
            leftcert=carolCert.pem
            right=192.168.0.1
            rightsubnet=10.1.0.0/16
            rightid="C=CH, O=strongSwan, CN=moon.strongswan.org"
            auto=start


3. Generating certificates and CRLs
   --------------------------------

This section is not a full-blown tutorial on how to use OpenSSL or the
strongSwan PKI tool.  It just lists a few points that are relevant if you want
to generate your own certificates and CRLs for use with strongSwan.


3.1 Generating a CA certificate
    ---------------------------

The OpenSSL statement

    openssl req -x509 -days 1460 -newkey rsa:4096 \
                -keyout strongswanKey.pem -out strongswanCert.pem

creates a 4096 bit RSA private key strongswanKey.pem and a self-signed CA
certificate strongswanCert.pem with a validity of 4 years (1460 days).

    openssl x509 -in cert.pem -noout -text

lists the properties of  a X.509 certificate cert.pem. It allows you to verify
whether the configuration defaults in openssl.cnf have been inserted correctly.

If you prefer the CA certificate to be in binary DER format then the following
command achieves this transformation:

     openssl x509 -in strongswanCert.pem -outform DER -out strongswanCert.der

The statements

    ipsec pki --gen -s 4096 > strongswanKey.der
    ipsec pki --self --ca --lifetime 1460 --in strongswanKey.der \
              --dn "C=CH, O=strongSwan, CN=strongSwan Root CA" \
              > strongswanCert.der
    ipsec pki --print --in strongswanCert.der

achieve about the same with the strongSwan PKI tool.  Unlike OpenSSL the tool
stores keys and certificates in the binary DER format by default.  The --outform
option may be used to write PEM encoded files.

The directory /etc/ipsec.d/cacerts contains all required CA certificates either
in binary DER or in base64 PEM format, irrespective of the file suffix the
correct format will be determined.


3.2 Generating a host or user certificate
    -------------------------------------

The OpenSSL statement

     openssl req -newkey rsa:2048 -keyout hostKey.pem \
                 -out hostReq.pem

generates a 2048 bit RSA private key hostKey.pem and a certificate request
hostReq.pem which has to be signed by the CA.

If you want to add a subjectAltName field to the host certificate you must edit
the OpenSSL configuration file openssl.cnf and add the following line in the
[ usr_cert ] section:

     subjectAltName=DNS:moon.strongswan.org

if you want to identify the host by its Fully Qualified Domain Name (FQDN), or

     subjectAltName=IP:192.168.0.1

if you want the ID to be of type IPV4_ADDR. Of course you could include both
ID types with

     subjectAltName=DNS:moon.strongswan.org,IP:192.168.0.1

but the use of an IP address for the identification of a host should be
discouraged anyway.

For user certificates the appropriate ID type is RFC822_ADDR which can be
specified as

     subjectAltName=email:carol@strongswan.org

or if the user's e-mail address is part of the subject's distinguished name

     subjectAltName=email:copy

Now the certificate request can be signed by the CA with the command

     openssl ca -in hostReq.pem -days 730 -out hostCert.pem -notext

If you omit the -days option then the default_days value (365 days) specified
in openssl.cnf is used.  The -notext option avoids that a human readable
listing of the certificate is prepended to the base64 encoded certificate
body.

If you want to use the dynamic CRL fetching feature described in section 4.7
then you may include one or several crlDistributionPoints in your end
certificates.  This can be done in the [ usr_cert ] section of the openssl.cnf
configuration file:

    crlDistributionPoints=@crl_dp

    [ crl_dp ]

    URI.1="http://crl.strongswan.org/strongswan.crl"
    URI.2="ldap://ldap.strongswan.org/cn=strongSwan Root CA, o=strongSwan,
           c=CH?certificateRevocationList"

If you have only a single HTTP distribution point then the short form

    crlDistributionPoints="URI:http://crl.strongswan.org/strongswan.crl"

also works.

Again the statements

    ipsec pki --gen > moonKey.der
    ipsec pki --pub --in moonKey.der | ipsec pki --issue --lifetime 730 \
              --cacert strongswanCert.der --cakey strongswanKey.der \
              --dn "C=CH, O=strongSwan, CN=moon.strongswan.org" \
              --san moon.strongswan.org --san 192.168.0.1 \
              --crl http://crl.strongswan.org/strongswan.crl > moonCert.der

do something thing similar using the strongSwan PKI tool.

Usually, a Windows or Mac OS X (or iOS) based VPN client needs its private key,
its host or user certificate, and the CA certificate. The most convenient way
to load this information is to put everything into a PKCS#12 file:

     openssl pkcs12 -export -inkey carolKey.pem \
                    -in carolCert.pem -name "carol" \
                    -certfile strongswanCert.pem -caname "strongSwan Root CA" \
                    -out carolCert.p12


3.3 Generating a CRL
    ----------------

An empty CRL that is signed by the CA can be generated with the command

     openssl ca -gencrl -crldays 15 -out crl.pem

If you omit the -crldays option then the default_crl_days value (30 days)
specified in openssl.cnf is used.

If you prefer the CRL to be in binary DER format then this conversion
can be achieved with

     openssl crl -in crl.pem -outform DER -out cert.crl

The strongSwan PKI tool provides the ipsec pki --signcrl command to sign CRLs.

The directory /etc/ipsec.d/crls contains all CRLs either in binary DER
or in base64 PEM format, irrespective of the file suffix the correct format
will be determined.


3.4 Revoking a certificate
    ----------------------

A specific host certificate stored in the file host.pem is revoked with the
command

     openssl ca -revoke host.pem

Next the CRL file must be updated

     openssl ca -gencrl -crldays 60 -out crl.pem

The content of the CRL file can be listed with the command

     openssl crl -in crl.pem -noout -text

in the case of a base64 CRL, or alternatively for a CRL in DER format

     openssl crl -inform DER -in cert.crl -noout -text

Again the ipsec pki --signcrl command may be used to create new CRLs containing
additional certificates.


4. Configuring the connections - ipsec.conf
   ----------------------------------------

4.1 Configuring my side
    -------------------

Usually the local side is the same for all connections.  Therefore it makes
sense to put the definitions characterizing the strongSwan security gateway into
the conn %default section of the configuration file /etc/ipsec.conf.  If we
assume throughout this document that the strongSwan security gateway is left and
the peer is right then we can write

conn %default
     leftcert=moonCert.pem
     # load connection definitions automatically
     auto=add

The X.509 certificate by which the strongSwan security gateway will authenticate
itself by sending it in binary form to its peers as part of the Internet Key
Exchange (IKE) is specified in the line

     leftcert=moonCert.pem

The certificate can either be stored in base64 PEM-format or in the binary
DER-format. Irrespective of the file suffix the correct format will be
determined.  Therefore

     leftcert=moonCert.der

or

     leftcert=moonCert.cer

would also be valid alternatives.

When using relative pathnames as in the examples above, the certificate files
must be stored in in the directory /etc/ipsec.d/certs.  In order to distinguish
strongSwan's own certificates from locally stored trusted peer certificates
(see section 5.5 for details), they could also be stored in a subdirectory
below /etc/ipsec.d/certs as e.g. in

    leftcert=mycerts/moonCert.pem

Absolute pathnames are also possible as in

    leftcert=/usr/ssl/certs/moonCert.pem

As an ID for the VPN gateway we recommend the use of a Fully Qualified Domain
Name (FQDN) of the form

conn rw
     right=%any
     leftid=@moon.strongswan.org

Important: When a FQDN identifier is used it must be explicitly included as a
so called subjectAltName of type dnsName (DNS:) in the certificate indicated
by leftcert.  For details on how to generate certificates with subjectAltNames,
please refer to section 3.2.

If you don't want to mess with subjectAltNames, you can use the certificate's
Distinguished Name (DN) instead, which is an identifier of type DER_ASN1_DN
and which can be written e.g. in the LDAP-type format

conn rw
     right=%any
     leftid="C=CH, O=strongSwan, CN=moon.strongswan.org"

Since the subject's DN is part of the certificate, the leftid does not have to
be declared explicitly. Thus the entry

conn rw
     right=%any

automatically assumes the subject DN of leftcert to be the host ID.


4.2 Multiple certificates
    ---------------------

strongSwan supports multiple local host certificates and corresponding
RSA private keys:

conn rw1
     right=%any
     rightid=@peer1.domain1
     leftcert=myCert1.pem
     # leftid is DN of myCert1

conn rw2
     right=%any
     rightid=@peer2.domain2
     leftcert=myCert2.pem
     # leftid is DN of myCert2

When peer1 initiates a connection then strongSwan will send myCert1 and will
sign with myKey1 defined in /etc/ipsec.secrets (see section 6.2) whereas
myCert2 and myKey2 will be used in a connection setup started from peer2.


4.3 Configuring the peer side using CA certificates
    -----------------------------------------------

Now we can proceed to define our connections.  In many applications we might
have dozens of road warriors connecting to a central strongSwan security
gateway. The following most simple statement:

conn rw
     right=%any

defines the general roadwarrior case.  The line right=%any literally means that
any IPsec peer is accepted, regardless of its current IP source address and its
ID, as long as the peer presents a valid X.509 certificate signed by a CA the
strongSwan security gateway puts explicit trust in.  Additionally, the signature
during IKE gives proof that the peer is in possession of the private RSA key
matching the public key contained in the transmitted certificate.

The ID by which a peer is identifying itself during IKE can by any of the ID
types IPV[46]_ADDR, FQDN, RFC822_ADDR or DER_ASN1_DN.  If one of the first
three ID types is used, then the accompanying X.509 certificate of the peer
must contain a matching subjectAltName field of the type ipAddress (IP:),
dnsName (DNS:) or rfc822Name (email:), respectively.  With the fourth type
DER_ASN1_DN the identifier must completely match the subject field of the
peer's certificate.  One of the two possible representations of a
Distinguished Name (DN) is the LDAP-type format

     rightid="C=CH, O=strongSwan IPsec, CN=sun.strongswan.org"

Additional whitespace can be added everywhere as desired since it will be
automatically eliminated by the X.509 parser.  An exception is the single
whitespace between individual words, like e.g. in strongSwan IPsec, which is
preserved by the parser.

The Relative Distinguished Names (RDNs) can alternatively be separated by a
slash '/' instead of a comma ','

     rightid="/C=CH/O=strongSwan IPsec/CN=sun.strongswan.org"

This is the representation extracted from the certificate by the OpenSSL
command line option

     openssl x509 -in sunCert.pem -noout -subject

The following RDNs are supported by strongSwan

+-------------------------------------------------------+
| DC                   Domain Component                 |
|-------------------------------------------------------|
| C                    Country                          |
|-------------------------------------------------------|
| ST                   State or province                |
|-------------------------------------------------------|
| L                    Locality or town                 |
|-------------------------------------------------------|
| O                    Organization                     |
|-------------------------------------------------------|
| OU                   Organizational Unit              |
|-------------------------------------------------------|
| CN                   Common Name                      |
|-------------------------------------------------------|
| ND                   NameDistinguisher, used with CN  |
|-------------------------------------------------------|
| N                    Name                             |
|-------------------------------------------------------|
| G                    Given name                       |
|-------------------------------------------------------|
| S                    Surname                          |
|-------------------------------------------------------|
| I                    Initials                         |
|-------------------------------------------------------|
| T                    Personal title                   |
|-------------------------------------------------------|
| E                    E-mail                           |
|-------------------------------------------------------|
| Email                E-mail                           |
|-------------------------------------------------------|
| emailAddress         E-mail                           |
|-------------------------------------------------------|
| SN                   Serial number                    |
|-------------------------------------------------------|
| serialNumber         Serial number                    |
|-------------------------------------------------------|
| D                    Description                      |
|-------------------------------------------------------|
| ID                   X.500 Unique Identifier          |
|-------------------------------------------------------|
| UID                  User ID                          |
|-------------------------------------------------------|
| TCGID                [Siemens] Trust Center Global ID |
|-------------------------------------------------------|
| UN                   Unstructured Name                |
|-------------------------------------------------------|
| unstructuredName     Unstructured Name                |
|-------------------------------------------------------|
| UA                   Unstructured Address             |
|-------------------------------------------------------|
| unstructuredAddress  Unstructured Address             |
|-------------------------------------------------------|
| EN                   Employee Number                  |
|-------------------------------------------------------|
| employeeNumber       Employee Number                  |
|-------------------------------------------------------|
| dnQualifier          DN Qualifier                     |
+-------------------------------------------------------+

With the roadwarrior connection definition listed above, an IPsec SA for
the strongSwan security gateway moon.strongswan.org itself can be established.
If any roadwarrior should be able to reach e.g. the two subnets 10.1.0.0/24
and 10.1.3.0/24 behind the security gateway then the following connection
definitions will make this possible

conn rw1
     right=%any
     leftsubnet=10.1.0.0/24

conn rw3
     right=%any
     leftsubnet=10.1.3.0/24

For IKEv2 connections this can even be simplified by using

    leftsubnet=10.1.0.0/24,10.1.3.0/24

If not all peers in possession of a X.509 certificate signed by a specific
certificate authority shall be given access to the Linux security gateway,
then either a subset of them can be barred by listing the serial numbers of
their certificates in a certificate revocation list (CRL) as specified in
section 5.2 or as an alternative, access can be controlled by explicitly
putting a roadwarrior entry for each eligible peer into ipsec.conf:

conn sun
     right=%any
     rightid=@sun.strongswan.org

conn carol
     right=%any
     rightid=carol@strongswan.org

conn dave
     right=%any
     rightid="C=CH, O=strongSwan, CN=dave@strongswan.org"

When the IP address of a peer is known to be stable, it can be specified as
well.  This entry is mandatory when the strongSwan host wants to act as the
initiator of an IPsec connection.

conn sun
     right=192.168.0.2
     rightid=@sun.strongswan.org

conn carol
     right=192.168.0.100
     rightid=carol@strongswan.org

conn dave
     right=192.168.0.200
     rightid="C=CH, O=strongSwan, CN=dave@strongswan.org"

conn venus
     right=192.168.0.50

In the last example the ID types FQDN, RFC822_ADDR, DER_ASN1_DN and IPV4_ADDR,
respectively, were used.  Of course all connection definitions presented so far
have included the lines in the conn %defaults section, comprising among other
a leftcert entry.


4.4 Handling Virtual IPs and narrowing
    ----------------------------------

Often roadwarriors are behind NAT-boxes with IPsec passthrough, which causes
the inner IP source address of an IPsec tunnel to be different from the
outer IP source address usually assigned dynamically by the ISP.
Whereas the varying outer IP address can be handled by the right=%any
construct, the inner IP address or subnet must always be declared in a
connection definition. Therefore for the three roadwarriors rw1 to rw3
connecting to a strongSwan security gateway the following entries are
required in /etc/ipsec.conf:

conn rw1
     right=%any
     righsubnet=10.4.0.5/32

conn rw2
     right=%any
     rightsubnet=10.4.0.47/32

conn rw3
     right=%any
     rightsubnet=10.4.0.128/28

Because the charon daemon uses narrowing (even for IKEv1) these three entries
can be reduced to the single connection definition

conn rw
     right=%any
     rightsubnet=10.4.0.0/24

Any host will be accepted (of course after successful authentication based on
the peer's X.509 certificate only) if it declares a client subnet lying totally
within the brackets defined by the subnet definition (in our example
10.4.0.0/24).

This strongSwan feature can also be helpful with VPN clients getting a
dynamically assigned inner IP from a DHCP server located on the NAT router box.


4.5 Protocol and Port Selectors
    ---------------------------

strongSwan offer the possibility to restrict the protocol and optionally the
ports in an IPsec SA using the rightprotoport and leftprotoport parameters.

Some examples:

conn icmp
     right=%any
     rightprotoport=icmp
     leftid=@moon.strongswan.org
     leftprotoport=icmp

conn http
     right=%any
     rightprotoport=6
     leftid=@moon.strongswan.org
     leftprotoport=6/80

conn l2tp       # with port wildcard for Mac OS X Panther interoperability
     right=%any
     rightprotoport=17/%any
     leftid=@moon.strongswan.org
     leftprotoport=17/1701

conn dhcp
     right=%any
     rightprotoport=udp/bootpc
     leftid=@moon.strongswan.org
     leftsubnet=0.0.0.0/0  #allows DHCP discovery broadcast
     leftprotoport=udp/bootps
     rekey=no
     keylife=20s
     rekeymargin=10s
     auto=add

Protocols and ports can be designated either by their numerical values
or by their acronyms defined in /etc/services.

    ipsec status

shows the following connection definitions:

"icmp": 192.168.0.1[@moon.strongswan.org]:1/0...%any:1/0
"http": 192.168.0.1[@moon.strongswan.org]:6/80...%any:6/0
"l2tp": 192.168.0.1[@moon.strongswan.org]:17/1701...%any:17/%any
"dhcp": 0.0.0.0/0===192.168.0.1[@moon.strongswan.org]:17/67...%any:17/68

Based on the protocol and port selectors appropriate policies will be set
up, so that only the specified payload types will pass through the IPsec
tunnel.


4.6 IPsec policies based on wildcards
    ---------------------------------

In large VPN-based remote access networks there is often a requirement that
access to the various parts of an internal network must be granted selectively,
e.g. depending on the group membership of the remote access user.  strongSwan
makes this possible by applying wildcard filtering on the VPN user's
distinguished name (ID_DER_ASN1_DN).

Let's make a practical example:

An organization has a sales department (OU=Sales) and a research group
(OU=Research).  In the company intranet there are separate subnets for Sales
(10.0.0.0/24) and Research (10.0.1.0/24) but both groups share a common web
server (10.0.2.100).  The VPN clients use Virtual IP addresses that are either
assigned statically or from a dynamic pool.  The sales and research departments
use IP addresses from separate address pools (10.1.0.0/24) and (10.1.1.0/24),
respectively.  An X.509 certificate is issued to each employee, containing in
its subject distinguished name the country (C=CH), the company (O=ACME),
the group membership(OU=Sales or OU=Research) and the common name (e.g.
CN=Bart Simpson).

The IPsec policy defined above can now be enforced with the following three
IPsec security associations:

conn sales
     right=%any
     rightid="C=CH, O=ACME, OU=Sales, CN=*"
     rightsubnet=10.1.0.0/24         # Sales IP range
     leftsubnet=10.0.0.0/24          # Sales subnet

conn research
     right=%any
     rightid="C=CH, O=ACME, OU=Research, CN=*"
     rightsubnet=10.1.1.0/24         # Research IP range
     leftsubnet=10.0.1.0/24          # Research subnet

conn web
     right=%any
     rightid="C=CH, O=ACME, OU=*, CN=*"
     rightsubnet=10.1.0.0/23         # Remote access IP range
     leftsubnet=10.0.2.100/32        # Web server
     rightprotoport=tcp              # TCP protocol only
     leftprotoport=tcp/http          # TCP port 80 only

The '*' character is used as a wildcard in relative distinguished names (RDNs).
In order to match a wildcard template, the ID_DER_ASN1_DN of a peer must contain
the same number of RDNs (selected from the list in section 4.3) appearing in the
exact order defined by the template.

    "C=CH, O=ACME, OU=Research, OU=Special Effects, CN=Bart Simpson"

matches the templates

    "C=CH, O=ACME, OU=Research, OU=*, CN=*"

    "C=CH, O=ACME, OU=*, OU=Special Effects, CN=*"

    "C=CH, O=ACME, OU=*, OU=*, CN=*"

but not the template

    "C=CH, O=ACME, OU=*, CN=*"

which doesn't have the same number of RDNs.


4.7 IPsec policies based on CA certificates
    ---------------------------------------

As an alternative to the wildcard based IPsec policies described in section 4.6,
access to specific client host and subnets can be controlled on the basis of
the CA that issued the peer certificate


conn sales
     right=%any
     rightca="C=CH, O=ACME, OU=Sales, CN=Sales CA"
     rightsubnet=10.1.0.0/24         # Sales IP range
     leftsubnet=10.0.0.0/24          # Sales subnet

conn research
     right=%any
     rightca="C=CH, O=ACME, OU=Research, CN=Research CA"
     rightsubnet=10.1.1.0/24         # Research IP range
     leftsubnet=10.0.1.0/24          # Research subnet

conn web
     right=%any
     rightca="C=CH, O=ACME, CN=ACME Root CA"
     rightsubnet=10.1.0.0/23         # Remote access IP range
     leftsubnet=10.0.2.100/32        # Web server
     rightprotoport=tcp              # TCP protocol only
     leftprotoport=tcp/http          # TCP port 80 only

In the example above, the connection "sales" can be used by peers
presenting certificates issued by the Sales CA, only.  In the same way,
the use of the connection "research" is restricted to owners of certificates
issued by the Research CA.  The connection "web" is open to both "Sales" and
"Research" peers because the required "ACME Root CA" is the issuer of the
Research and Sales intermediate CAs.  If no rightca parameter is present
then any valid certificate issued by one of the trusted CAs in
/etc/ipsec.d/cacerts can be used by the peer.

The leftca parameter usually doesn't have to be set explicitly because
by default it is set to the issuer field of the certificate loaded via
leftcert.  The statement

     rightca=%same

sets the CA requested from the peer to the CA used by the left side itself
as e.g. in

conn sales
     right=%any
     rightca=%same
     leftcert=mySalesCert.pem


5. Configuring certificates and CRLs
   ---------------------------------


5.1 Installing the CA certificates
    ------------------------------

X.509 certificates received by strongSwan during the IKE protocol are
automatically authenticated by going up the trust chain until a self-signed
root CA certificate is reached.  Usually host certificates are directly signed
by a root CA, but strongSwan also supports multi-level hierarchies with
intermediate CAs in between.  All CA certificates belonging to a trust chain
must be copied in either binary DER or base64 PEM format into the directory

     /etc/ipsec.d/cacerts/


5.2 Installing optional certificate revocation lists (CRLs)
    -------------------------------------------------------

By copying a CA certificate into /etc/ipsec.d/cacerts/, automatically all user
or host certificates issued by this CA are declared valid.  Unfortunately,
private keys might get compromised inadvertently or intentionally, personal
certificates of users leaving a company have to be blocked immediately, etc.
To this purpose certificate revocation lists (CRLs) have been created.  CRLs
contain the serial numbers of all user or host certificates that have been
revoked due to various reasons.

After successful verification of the X.509 trust chain, strongSwan searches its
list of CRLs either obtained by loading them from the /etc/ipsec.d/crls/
directory or fetching them dynamically from a HTTP or LDAP server for the
presence of a CRL issued by the CA that has signed the certificate.

If the serial number of the certificate is found in the CRL then the public key
contained in the certificate is declared invalid and the IPsec SA will not be
established.  If no CRL is found or if the deadline defined in the nextUpdate
field of the CRL has been reached, a warning is issued but the public key will
nevertheless be accepted.  CRLs must be stored either in binary DER or base64
PEM format in the crls directory.


5.3 Dynamic update of certificates and CRLs
    ---------------------------------------

strongSwan reads certificates and CRLs from their respective files during system
startup and keeps them in memory.  X.509 certificates have a finite life span
defined by their validity field.  Therefore it must be possible to replace CA or
OCSP certificates kept in system memory without disturbing established IKE SAs.
Certificate revocation lists should also be updated in the regular intervals
indicated by the nextUpdate field in the CRL body.  The following interactive
commands allow the manual replacement of the various files:

+---------------------------------------------------------------------------+
| ipsec rereadsecrets       reload file /etc/ipsec.secrets                  |
|---------------------------------------------------------------------------|
| ipsec rereadcacerts       reload all files in /etc/ipsec.d/cacerts/       |
|---------------------------------------------------------------------------|
| ipsec rereadaacerts       reload all files in /etc/ipsec.d/aacerts/       |
|---------------------------------------------------------------------------|
| ipsec rereadocspcerts     reload all files in /etc/ipsec.d/ocspcerts/     |
|---------------------------------------------------------------------------|
| ipsec rereadacerts        reload all files in /etc/ipsec.d/acerts/        |
|---------------------------------------------------------------------------|
| ipsec rereadcrls          reload all files in /etc/ipsec.d/crls/          |
|---------------------------------------------------------------------------|
| ipsec rereadall           ipsec rereadsecrets                             |
|                                 rereadcacerts                             |
|                                 rereadaacerts                             |
|                                 rereadocspcerts                           |
|                                 rereadacerts                              |
|                                 rereadcrls                                |
|---------------------------------------------------------------------------|
| ipsec purgeocsp           purge the OCSP cache and fetching requests      |
+---------------------------------------------------------------------------+

CRLs can also be automatically fetched from an HTTP or LDAP server by using
the CRL distribution points contained in X.509 certificates.


5.4 Local caching of CRLs
    ---------------------

The the ipsec.conf option

   config setup
        cachecrls=yes

activates the local caching of CRLs that were dynamically fetched from an
HTTP or LDAP server.  Cached copies are stored in /etc/ipsec.d/crls using a
unique filename formed from the issuer's SubjectKeyIdentifier and the
suffix .crl.

With the cached copy the CRL is immediately available after startup.  When the
local copy is about to expire it is automatically replaced with an updated CRL
fetched from one of the defined CRL distribution points.


5.5 Online Certificate Status Protocol (OCSP)
    -----------------------------------------

The Online Certificate Status Protocol is defined by RFC 2560.  It can be
used to query an OCSP server about the current status of an X.509 certificate
and is often used as a more dynamic alternative to a static Certificate
Revocation List (CRL).  Both the OCSP request sent by the client and the OCSP
response messages returned by the server are transported via a standard
TCP/HTTP connection.  Therefore cURL support must be enabled during
configuration.

In the simplest OCSP setup, a default URI under which the OCSP server for a
given CA can be accessed is defined in ipsec.conf:

   ca strongswan
        cacert=strongswanCert.pem
        ocspuri=http://ocsp.strongswan.org:8880
        auto=add

The HTTP port can be freely chosen.

OpenSSL implements an OCSP server that can be used in conjunction with an
openssl-based Public Key Infrastructure.  The OCSP server is started with the
following command:

    openssl ocsp -index index.txt -CA strongswanCert.pem -port 8880 \
                 -rkey ocspKey.pem -rsigner ocspCert.pem \
                 -resp_no_certs -nmin 60 -text

The command consists of the parameters

 -index    index.txt is a copy of the OpenSSL index file containing the list of
           all issued certificates.  The certificate status in index.txt
           is designated either by V for valid or R for revoked.  If a new
           certificate is added or if a certificate is revoked using the
           openssl ca command, the OCSP server must be restarted in order for
           the changes in index.txt to take effect.

 -CA       the CA certificate

 -port     the HTTP port the OCSP server is listening on.

 -rkey     the private key used to sign the OCSP response.  The use of the
           sensitive CA private key is not recommended since this could
           jeopardize the security of your production PKI if the OCSP
           server is hacked.  It is much better to generate a special
           RSA private key just for OCSP signing use instead.

 -rsigner  the certificate of the OCSP server containing a public key which
           matches the private key defined by -rkey and which can be used by
           the client to check the trustworthiness of the signed OCSP response.

 -resp_no_certs  With this option the OCSP signer certificate defined by
                 -rsigner is not included in the OCSP response.

 -nmin     the validity interval of an OCSP response given in minutes.

 -text     this option activates a verbose logging output, showing the contents
           of both the received OCSP request and sent OCSP response.


The OCSP signer certificate can either be put into the default directory

    /etc/ipsec.d/ocspcerts

or alternatively strongSwan can receive it as part of the OCSP response from the
remote OCSP server.  In order to verify that the server is indeed authorized by
a CA to deal out certificate status information an extended key usage attribute
must be included in the OCSP server certificate.  Just insert the parameter

    extendedKeyUsage=OCSPSigner

in the [ usr_cert ] section of your openssl.cnf configuration file before
the CA signs the OCSP server certificate.

For a given CA the corresponding ca section in ipsec.conf (see section 7) allows
to define the URI of a single OCSP server.  As an alternative an OCSP URI can be
embedded into each host and user certificate by putting the line

    authorityInfoAccess = OCSP;URI:http://ocsp.strongswan.org:8880

into the [ usr_cert ] section of your openssl.cnf configuration file.
If an OCSP authorityInfoAccess extension is present in a certificate then this
record overrides the default URI defined by the ca section.


5.6 CRL Policy
    ----------

By default strongSwan is quite tolerant concerning the handling of CRLs. It is
not mandatory for a CRL to be present in /etc/ipsec.d/crls and if the expiration
date defined by the nextUpdate field of a CRL has been reached just a warning
is issued but a peer certificate will always be accepted if it has not been
revoked.

If you want to enforce a stricter CRL policy then you can do this by setting
the "strictcrlpolicy" option.  This is done in the "config setup" section
of the ipsec.conf file:

    config setup
         strictcrlpolicy=yes
          ...

A certificate received from a peer will not be accepted if no corresponding
CRL or OCSP response is available.  And if an ISAKMP SA re-negotiation takes
place after the nextUpdate deadline has been reached, the peer certificate
will be declared invalid and the cached RSA public key will be deleted, causing
the connection in question to fail.  Therefore if you are going to use the
"strictcrlpolicy=yes" option, make sure that the CRLs will always be updated
in time.  Otherwise a total standstill would ensue.

As mentioned earlier the default setting is "strictcrlpolicy=no"


5.7 Configuring the peer side using locally stored certificates
    -----------------------------------------------------------

If you don't want to use trust chains based on CA certificates as proposed in
section 4.3 you can alternatively import trusted peer certificates directly.
Thus you do not have to rely on the certificate to be transmitted by the peer
as part of the IKE protocol.

With the conn %default section defined in section 4.1 and the use of the
rightcert keyword for the peer side, the connection definitions in section 4.3
can alternatively be written as

    conn sun
          right=%any
          rightid=@sun.strongswan.org
          rightcert=sunCert.cer

     conn carol
          right=192.168.0.100
          rightcert=carolCert.der

If the peer certificates are loaded locally then there is no sense in sending
any certificates to the other end via the IKE protocol.  Especially if
self-signed certificates are used which wouldn't be accepted anyway by
the other side.  In these cases it is recommended to add

    leftsendcert=never

to the connection definition[s] in order to avoid the sending of the host's
own certificate.  The default value is

    leftsendcert=ifasked

If a peer does not send a certificate request then use the setting

    leftsendcert=always

If a peer certificate contains a subjectAltName extension, then an alternative
rightid type can be used, as the example "conn sun" shows.  If no rightid
entry is present then the subject distinguished name contained in the
certificate is taken as the ID.

Using the same rules concerning pathnames that apply to strongSwan's own
certificates, the following two definitions are also valid for trusted peer
certificates:

    rightcert=peercerts/carolCert.der

or

    rightcert=/usr/ssl/certs/carolCert.der


6. Configuring the private keys - ipsec.secrets
   --------------------------------------------

6.1 Loading private key files in PKCS#1 or PKCS#8 format
    ----------------------------------------------------

Besides strongSwan's raw private key format strongSwan has been enabled to
load RSA (or ECDSA) private keys in the PKCS#1 or PKCS#8 file format.
The key files can be optionally secured with a passphrase.

RSA private key files are declared in /etc/ipsec.secrets using the syntax

    : RSA <my keyfile> "<optional passphrase>"

The key file can be either in base64 PEM-format or binary DER-format.  The
actual coding is detected automatically.  The example

    : RSA moonKey.pem

uses a pathname relative to the default directory

    /etc/ipsec.d/private

As an alternative an absolute pathname can be given as in

    : RSA /usr/ssl/private/moonKey.pem

In both cases make sure that the key files are root readable only.

Often a private key must be transported from the Certification Authority
where it was generated to the target security gateway where it is going
to be used.  In order to protect the key it can be encrypted with a symmetric
cipher using a transport key derived from a cryptographically strong
passphrase.

Once on the security gateway the private key can either be permanently
unlocked so that it can be used by Pluto without having to know a
passphrase

    openssl rsa -in moonKey.pem -out moonKey.pem

or as an option the key file can remain secured.  In this case the passphrase
unlocking the private key must be added after the pathname in
/etc/ipsec.secrets

    : RSA moonKey.pem "This is my passphrase"

Some CAs distribute private keys embedded in a PKCS#12 file. Since strongSwan
is not yet able to read this format directly, the private key part must
first be extracted using the command

     openssl pkcs12 -nocerts -in moonCert.p12 -out moonKey.pem

if the key file moonKey.pem is to be secured again by a passphrase, or

     openssl pkcs12 -nocerts  -nodes -in moonCert.p12 -out moonKey.pem

if the private key is to be stored unlocked.


6.2 Entering passphrases interactively
    ----------------------------------

On a VPN gateway you would want to put the passphrase protecting the private
key file right into /etc/ipsec.secrets as described in the previous paragraph,
so that the gateway can be booted in unattended mode.  The risk of keeping
unencrypted secrets on a server can be minimized by putting the box into a
locked room.  As long as no one can get root access on the machine the private
keys are safe.

On a mobile laptop computer the situation is quite different.  The computer can
be stolen or the user is leaving it unattended so that unauthorized persons
can get access to it.  In theses cases it would be preferable not to keep any
passphrases openly in /etc/ipsec.secrets but to prompt for them interactively
instead.  This is easily done by defining

    : RSA moonKey.pem %prompt

Since strongSwan is usually started during the boot process, usually no
interactive console windows is available which can be used to prompt for
the passphrase.  This must be initiated by the user by typing

    ipsec secrets

which actually is an alias for the existing command

    ipsec rereadsecrets

and which causes a passphrase prompt to appear.  To abort entering a passphrase
enter just a carriage return.


6.3 Multiple private keys
    ---------------------

strongSwan supports multiple private keys. Since the connections defined
in ipsec.conf can find the correct private key based on the public key
contained in the certificate assigned by leftcert, default private key
definitions without specific IDs can be used

    : RSA myKey1.pem "<optional passphrase1>"

    : RSA myKey2.pem "<optional passphrase2>"


7. Configuring CA properties - ipsec.conf
   --------------------------------------

Besides the definition of IPsec connections the ipsec.conf file can also
be used to configure a few properties of the certification authorities
needed to establish the X.509 trust chains.  The following example shows
some of the parameters that are currently available:

    ca strongswan
       cacert=strongswanCert.pem
       ocspuri=http://ocsp.strongswan.org:8880
       crluri=http://crl.strongswan.org/strongswan.crl'
       crluri2="ldap://ldap.strongswan.org/O=strongSwan, C=CH?certificateRevocationList"
       auto=add

In a similar way as conn sections are used for connection definitions, an
arbitrary number of optional ca sections define the basic properties of CAs.

Each ca section is named with a unique label

       ca strongswan

The only mandatory parameter is

       cacert=strongswanCert.pem

which points to the CA certificate which usually resides in the default
directory /etc/ipsec.d/cacerts/ but could also be retrieved via an absolute
path name.

The OCSP URI

       ocspuri=http://ocsp.strongswan.org:8880

allows to define an individual OCSP server per CA.  Also up to two additional
CRL distribution points (CDPs) can be defined

       crluri=http://crl.strongswan.org/strongswan.crl'
       crluri2="ldap://ldap.strongswan.org/O=strongSwan, C=CH?certificateRevocationList"

which are added to any CDPs already present in the received certificates
themselves.

With the auto=add statement the ca definition is automatically loaded during
startup.  Setting auto=ignore will ignore the ca section.

Any parameters which appear in several ca definitions can be put in
a common ca %default section

    ca %default
       crluri=http://crl.strongswan.org/strongswan.crl'


8. Monitoring functions
   --------------------

strongSwan offers the following monitoring functions:

The command

    ipsec listalgs

lists all IKE cryptographic algorithms that are currently
registered with strongSwan.


The command

    ipsec listcerts [--utc]

lists all local certificates, both strongSwan's own and those of
trusted peer loaded via leftcert and rightcert, respectively.


The command

    ipsec listcacerts [--utc]

lists all CA certificates that have been either been loaded from the directory
/etc/ipsec.d/cacerts/ or received via the IKE protocol.


The command

    ipsec listaacerts [--utc]

lists all Authorization Authority certificates that have been loaded from
the directory /etc/ipsec.d/aacerts/.


The command

    ipsec listocspcerts [--utc]

lists all OCSO signer certificates that have been either loaded from
/etc/ipsec.d/ocspcerts/ or have been received included in the OCSP server
response.


The command

    ipsec listacerts [--utc]

lists all X.509 attribute certificates that have been loaded from the directory
/etc/ipsec.d/acerts/.


The command

    ipsec listcainfos [--utc]

lists the properties defined by the ca definition sections in ipsec.conf.


The command

    ipsec listcrls [--utc]

lists all CRLs that have been loaded from /etc/ipsec.d/crls/.


The command


    ipsec listocsp [--utc]

lists the contents of the OCSP response cache.


The command

    ipsec listall [--utc]

is equivalent to using all of the above commands.


9. Firewall support functions
   --------------------------


9.1 Environment variables in the updown script
    ------------------------------------------

strongSwan makes the following environment variables available
in the updown script indicated by the leftupdown option:

+-------------------------------------------------------------------+
| Variable               Example                    Comment         |
|-------------------------------------------------------------------|
| $PLUTO_PEER_ID         carol@strongswan.org       RFC822_ADDR (1) |
|-------------------------------------------------------------------|
| $PLUTO_PEER_PROTOCOL   17                         udp         (2) |
|-------------------------------------------------------------------|
| $PLUTO_PEER_PORT       68                         bootpc      (3) |
|-------------------------------------------------------------------|
| $PLUTO_PEER_CA         C=CH, O=ACME, CN=Sales CA              (4) |
|-------------------------------------------------------------------|
| $PLUTO_MY_ID           @moon.strongswan.org       FQDN        (1) |
|-------------------------------------------------------------------|
| $PLUTO_MY_PROTOCOL     17                         udp         (2) |
|-------------------------------------------------------------------|
| $PLUTO_MY_PORT         67                         bootps      (3) |
+-------------------------------------------------------------------+

(1) $PLUTO_PEER_ID/$PLUTO_MY_ID contain the IDs of the two ends
    of an established connection. In our examples these
    correspond to the strings defined by rightid and leftid,
    respectively.

(2) $PLUTO_PEER_PROTOCOL/$PLUTO_MY_PROTOCOL contain the protocol
    defined by the rightprotoport and leftprotoport options,
    respectively. Both variables contain the same protocol value.
    The variables take on the value '0' if no protocol has been defined.

(3) $PLUTO_PEER_PORT/$PLUTO_MY_PORT contain the ports defined by
    the rightprotoport and leftprotoport options, respectively.
    The variables take on the value '0' if no port has been defined.

(4) $PLUTO_PEER_CA contains the distinguished name of the CA that
    issued the peer's certificate.

There are several more, refer to the provided default script for a documentation
of these.


9.2 Automatic insertion and deletion of iptables firewall rules
    -----------------------------------------------------------

The default _updown script automatically inserts and deletes dynamic iptables
firewall rules upon the establishment or teardown, respectively, of an IPsec
security association.  This feature is activated with the line

   leftfirewall=yes

If you define a local client subnet with a netmask larger than /32 behind
the gateway then the automatically inserted FORWARD iptables rules will
not allow to access the internal IP address of the host although it is
part of the client subnet definition.  If you want additional INPUT and
OUTPUT iptables rules to be inserted, so that the host itself can be accessed
then add the following line:

   lefthostaccess=yes

The _updown script also features a logging facility which will register the
creation (+) and the expiration (-) of each successfully established VPN
connection in a special syslog file in the following concise and easily
readable format:

Jul 19 18:58:38 moon vpn:
    + @carol.strongswan.org  192.168.0.100 -- 192.168.0.1 == 10.1.0.0/16
Jul 19 22:15:17 moon vpn:
    - @carol.strongswan.org  192.168.0.100 -- 192.168.0.1 == 10.1.0.0/16
