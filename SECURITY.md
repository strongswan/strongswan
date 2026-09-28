# Security Policy

## Reporting a Vulnerability

Please report any security-relevant flaw to security@strongswan.org. Whenever
possible encrypt your email with the [strongSwan security PGP key](https://download.strongswan.org/STRONGSWAN-SECURITY-PGP-KEY)
with key ID 0x1EB41ECF25A536E4.

## Severity Classification

* **High Severity Flaw**

    * Allows remote access to the VPN with improper, missing, or invalid
      credentials
    * Allows local escalation of privileges on the server
    * Plain text traffic on the secure interface
    * Key generation and crypto flaws that reduce the difficulty in decrypting
      secure traffic

* **Medium Severity Flaw**

    * Remotely crashing the strongSwan daemon, which would allow DoS attacks on
      the VPN service

* **Low Severity Flaw**

    * All other minor issues not directly compromising security or availability
      of the strongSwan daemon or the host the daemon is running on

## Action Taken

For **high** and **medium** severity vulnerabilities we are generally going to
apply for a [CVE Identifier](https://www.cve.org/). On a predetermined date,
we officially issue an advisory and a patch for the vulnerability and usually
a new stable strongSwan release containing the security fix. We will notify all
known strongSwan license customers and the major Linux distributions about two
weeks before the publication to allow them to patch their software release.

Minor vulnerabilities of **low** severity usually will be fixed immediately
in our repository and released with the next stable release.

## List of Published and Fixed Security Flaws

A list of all published strongSwan high and medium security flaws can be found
[on our website](https://strongswan.org/security/), as can the corresponding
[security patches and OSV files](https://download.strongswan.org/security/).
Each security patch is signed by the
[strongSwan release PGP key](https://download.strongswan.org/STRONGSWAN-RELEASE-PGP-KEY).
