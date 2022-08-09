# ipsec scepclient #

## Description ##

The `ipsec scepclient` tool was an early client implementation of the
_Simple Certificate Enrollment Protocol_ (SCEP).

The tool was written in 2005 and only got marginal updates since then. Hence it
implemented an old version of the SCEP Internet Draft (version 10/11 of
`draft-nourse-scep` and used the broken `MD5` hash and single `DES` encryption
algorithms as defaults.

## Obsolescence ##

With strongSwan version 5.9.8 `*ipsec scepclient*` has been removed and replaced
by the `pki` subcommands `pki --scep` and `pki --scepca` which implement the new
SCEP RFC 8894 standard that was released in September 2020 and which supports
trusted **certificate renewal** based on the existing client certificate.
