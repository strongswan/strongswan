.DA "3 May 2001"
.ds LH "
.ds CH "Opportunistic Encryption
.ds RH "
.ds LF "Draft 4+
.ds CF "\\*(DY
.ds RF %
.de P
.LP
..
.de R
.LP
\fBRationale:\fR
..
.de A
.LP
\fBAhem:\fR
..
.TL
Opportunistic Encryption
.AU
Henry Spencer
D. Hugh Redelmeier
.AI
henry@spsystems.net
hugh@mimosa.com
Linux FreeS/WAN Project
.AB no
xxx cases where reverses not controlled, all possibilities.
xxx DHR suggests okay if gateway doesn't control reverse but destination does.
xxx level of patience where Responder just doesn't answer the phone.
xxx IKE finger to get basic keying info, to be confirmed via DNSSEC?
xxx packets from some OE connections might get special status,
if the other end is definitely someone we trust.
Opportunistic encryption permits secure (encrypted, authenticated)
communication via IPsec without connection-by-connection prearrangement,
either explicitly between hosts (when the hosts are capable of it) or
transparently via packet-intercepting security gateways.
It uses DNS records (authenticated with DNSSEC) to provide
the necessary information for gateway discovery and gateway authentication,
and constrains negotiation enough to guarantee success.
.sp
Substantive changes since draft 3:
write off inverse queries as a lost cause;
use Invalid-SPI rather than Delete as notification of unknown SA;
minor wording improvements and clarifications.
This document takes over from the older ``Implementing Opportunistic
Encryption'' document.
.AE
.NH 1
Introduction
.P
A major goal of the FreeS/WAN project is opportunistic encryption:
a (security) gateway intercepts an outgoing packet aimed at a
remote host, and quickly attempts to negotiate an IPsec tunnel to that
host's security gateway.
If the attempt succeeds, traffic can then be secure,
transparently (without changes to the host software).
If the attempt fails,
the packet (or a retry thereof) passes through in clear or is dropped,
depending on local policy.
Prearranged tunnels bypass the packet interception etc., so static VPNs
can coexist with opportunistic encryption.
.P
This generalizes trivially to the end-to-end case:
host and security gateway simply are one and the same.
Some optimizations are possible in that case,
but the basic scheme need not change.
.P
The objectives for security systems need to be explicitly stated.
Opportunistic encryption is meant to achieve secure communication,
without prearrangement of the individual connection
(although some prearrangement on a per-host basis is required),
between any two hosts which implement the protocol
(and, if they act as security gateways,
between hosts behind them).
Here ``secure'' means strong encryption and authentication of packets,
with authentication of participants\(emto prevent man-in-the-middle
and impersonation attacks\(emdependent on several factors.
The biggest factor is the authentication of DNS records,
via DNSSEC or equivalent means.
A lesser factor is which exact variant
of the setup procedure (see section 2.2) is used,
because there is a tradeoff between strong authentication of the other end
and ability
to negotiate opportunistic encryption with hosts which have limited
or no control of their reverse-map DNS records:
without reverse-map information,
we can verify that the host has the right to use a particular FQDN
(Fully Qualified Domain Name),
but not whether that FQDN is authorized to use that IP address.
Local policy must decide whether authentication
or connectivity has higher priority.
.P
Apart from careful attention to detail in various areas,
there are three crucial design problems for opportunistic encryption.
It needs a way to quickly identify the remote host's security gateway.
It needs a way to quickly obtain an authentication key for the
security gateway.
And the numerous options which can be specified with IKE
must be constrained sufficiently that two independent implementations are
guaranteed to reach agreement,
without any explicit prearrangement or preliminary negotiation.
The first two problems are solved using DNS,
with DNSSEC ensuring that the data obtained is reliable;
the third is solved by specifying a minimum standard which must be supported.
.P
A note on philosophy:
we have deliberately avoided providing six different
ways to do each job, in favor of specifying one good one.
Choices are
provided only when they appear to be necessary,
or at least important.
.P
A note on terminology:
to avoid constant circumlocutions,
an ISAKMP/IKE SA, possibly recreated occasionally by rekeying,
will be referred to as a ``keying channel'',
and a set of IPsec SAs providing bidirectional communication between
two IPsec hosts,
possibly recreated occasionally by rekeying,
will be referred to as a ``tunnel''
(it could conceivably use transport mode in the host-to-host case,
but we advocate using tunnel mode even there).
The word ``connection'' is here used in a more generic sense.
The word ``lifetime'' will be avoided in favor of ``rekeying interval'',
since many of the connections will have useful lives far shorter
than any reasonable rekeying interval,
and hence the two concepts must be separated.
.P
A note on document structure:
Discussions of \fIwhy\fR things were done a particular way,
or not done a particular way,
are broken out in paragraphs headed ``Rationale:''
(to preserve the flow of the text, many such paragraphs are deferred
to the ends of sections).
Paragraphs headed ``Ahem:'' are discussions of where the problem is being
made significantly harder by problems elsewhere,
and how that might be corrected.
Some meta-comments are enclosed in [].
.R
The motive is to get the Internet encrypted.
That requires encryption without connection-by-connection prearrangement:
a system must be able to
reliably negotiate an encrypted, authenticated
connection with a total stranger.
While end-to-end encryption is preferable,
doing opportunistic encryption in security gateways
gives enormous leverage for quick deployment of this technology,
in a world where end-host software is often primitive, rigid, and outdated.
.R
Speed is of the essence in tunnel setup:
a connection-establishment delay longer than about 10 seconds
begins to cause problems for users and applications.
Thus the emphasis on rapidity in gateway discovery and key fetching.
.A
Host-to-host opportunistic encryption
would be utterly trivial if a fast public-key
encryption/signature
algorithm was available.
You would do a reverse lookup on the destination address to obtain a
public key for that address,
and simply encrypt all packets going to it with that key,
signing them with your own private key.
Alas, this is impractical with current CPU speeds and current algorithms
(although as noted later, it might be of some use for limited purposes).
Nevertheless, it is a useful model.
.NH 1
Connection Setup
.P
For purposes of discussion, the network is taken to look like this:
.DS
Source----Initiator----...----Responder----Destination
.DE
The intercepted packet comes from the Source,
bound for the Destination,
and is intercepted at the Initiator.
The Initiator communicates over the insecure Internet to the Responder.
The Source and the Initiator might be the same host,
or the Source might be an end-user host and the Initiator a
security gateway (SG).
Likewise for the Responder and the Destination.
.P
Given an intercepted packet,
whose useful information (for our purposes)
is essentially only the Destination's IP address,
the Initiator
must quickly determine the Responder (the Destination's SG) and
fetch everything needed to authenticate it.
The Responder must do likewise for the Initiator.
Both must eventually also confirm that the other is authorized to act
on behalf of the client host behind it (if any).
.P
An important subtlety here is that if the alternative to an IPsec tunnel
is plaintext transmission, negative results must be obtained quickly.
That is,
the decision that \fIno\fR tunnel can be established must also be made rapidly.
.NH 2
Packet Interception
.P
Interception of outgoing packets is relatively straightforward
in principle.
It is preferable to put the intercepted packet on hold rather than
dropping it, since higher-level retries are not necessarily well-timed.
There is a problem of hosts and applications retrying during negotiations.
ARP implementations, which face the same problem,
use the approach of keeping the \fImost recent\fR
packet for an as-yet-unresolved address,
and throwing away older ones.
(Incrementing of request numbers etc. means that replies to older ones may no
longer be accepted.)
.P
Is it worth intercepting \fIincoming\fR packets, from the outside world, and
attempting tunnel setup based on them?
No, unless and until a way can be devised to initiate opportunistic encryption
to a non-opportunistic responder,
because
if the other end has not initiated tunnel setup itself, it will not be
prepared to do so at our request.
.R
Note, however, that most incoming packets will promptly be followed by
an outgoing packet in response!
Conceivably it might be useful to start early stages of negotiation,
at least as far as looking up information,
in response to an incoming packet.
.R
If a plaintext incoming packet indicates that the other
end is not prepared to do opportunistic encryption,
it might seem that this fact should be noted, to
avoid consuming resources and delaying
traffic in an attempt at opportunistic setup which is doomed to fail.
However, this would be a major security hole,
since the plaintext packet is not authenticated;
see section 2.5.
.NH 2
Algorithm
.P
For clarity,
the following defers most discussion of error handling to the end.
.nr x \w'Step 3A.'u+1n
.de S
.IP "Step \\$1." \nxu
..
.S 1
Initiator does a DNS reverse lookup on the Destination address,
asking not for the usual PTR records,
but for TXT records.
Meanwhile, Initiator also sends a ping to the Destination,
to cause any other dynamic setup actions to start happening.
(Ping replies are disregarded;
the host might not be reachable with plaintext pings.)
.S 2A
If at least one suitable TXT record (see section 2.3) comes back,
each contains a potential Responder's IP address
and that Responder's public key (or where to find it).
Initiator picks one TXT record, based on priority (see 2.3),
thus picking a Responder.
If there was no public key in the TXT record,
the Initiator also starts a DNS lookup (as specified by the TXT record)
to get KEY records.
.S 2B
If no suitable TXT record is available,
and policy permits,
Initiator designates the Destination itself as the Responder
(see section 2.4).
If policy does not permit,
or the Destination is unresponsive to the negotiation,
then opportunistic encryption is not possible,
and Initiator gives up (see section 2.5).
.S 3
If there already is a keying channel to the Responder's IP address,
the Initiator uses the existing keying channel;
skip to step 10.
Otherwise, the Initiator starts an IKE Phase 1 negotiation
(see section 2.7 for details)
with the Responder.
The address family of the Responder's IP address dictates whether
the keying channel and the outside of the tunnel should be IPv4 or IPv6.
.S 4
Responder gets the first IKE message,
and responds.
It also starts a DNS reverse lookup on the Initiator's IP address,
for KEY records, on speculation.
.S 5
Initiator gets Responder's reply,
and sends first message of IKE's D-H exchange (see 2.4).
.S 6
Responder gets Initiator's D-H message,
and responds with a matching one.
.S 7
Initiator gets Responder's D-H message;
encryption is now established, authentication remains to be done.
Initiator sends IKE authentication message,
with an FQDN identity if a reverse lookup on its address will not yield a
suitable KEY record.
(Note, an FQDN need not
actually correspond to a host\(eme.g., the DNS data for it need not
include an A record.)
.S 8
Responder gets Initiator's authentication message.
If there is no identity included,
Responder waits for step 4's speculative DNS lookup to finish;
it should yield a suitable KEY record (see 2.3).
If there is an FQDN identity,
responder discards any data obtained from step 4's DNS lookup;
does a forward lookup on the FQDN, for a KEY record;
waits for that lookup to return;
it should yield a suitable KEY record.
Either way, Responder uses the KEY data to verify the message's hash.
Responder replies with an authentication message,
with an FQDN identity if a reverse lookup on its address will not yield a
suitable KEY record.
.S 9A
(If step 2A was used.)
The Initiator gets the Responder's authentication message.
Step 2A has provided a key (from the TXT record or via DNS lookup).
Verify message's hash.
Encrypted and authenticated keying channel established,
man-in-middle attack precluded.
.S 9B
(If step 2B was used.)
The Initiator gets the Responder's authentication message,
which must contain an FQDN identity (if the Responder can't put a TXT in his
reverse map he presumably can't do a KEY either).
Do forward lookup on the FQDN,
get suitable KEY record, verify hash.
Encrypted keying channel established,
man-in-middle attack precluded,
but authentication weak (see 2.4).
.S 10
Initiator initiates IKE Phase 2 negotiation (see 2.7) to establish tunnel,
specifying Source and Destination identities as IP addresses (see 2.6).
The address family of those addresses also determines whether the inside
of the tunnel should be IPv4 or IPv6.
.S 11
Responder gets first Phase 2 message.
Now the Responder finally knows what's going on!
Unless the specified Source is identical to the Initiator,
Responder initiates DNS reverse lookup on Source IP address,
for TXT records;
waits for result;
gets suitable TXT record(s) (see 2.3),
which should contain either the Initiator's IP address
or an FQDN identity identical to that supplied by the Initiator in step 7.
This verifies that the Initiator is authorized
to act as SG for the Source.
Responder replies with second Phase 2 message,
selecting acceptable details (see 2.7),
and establishes tunnel.
.S 12
Initiator gets second Phase 2 message,
establishes tunnel (if he didn't already),
and releases the intercepted packet into it, finally.
.S 13
Communication proceeds.
See section 3 for what happens later.
.P
As additional information becomes available,
notably in steps 1, 2, 4, 8, 9, 11, and 12,
there is always a possibility that local policy
(e.g., access limitations) might prevent further progress.
Whenever possible,
at least attempt to inform the other end of this.
.P
At any time, there is a possibility of the negotiation failing due to
unexpected responses, e.g. the Responder not responding at all
or rejecting all Initiator's proposals.
If multiple SGs were found as possible Responders,
the Initiator should try at least one more before giving up.
The number tried should be influenced by what the alternative is:
if the traffic will otherwise be discarded, trying the full list is
probably appropriate,
while if the alternative is plaintext transmission,
it might be based on how long the tries are taking.
The Initiator should try as many as it reasonably can,
ideally all of them.
.P
There is a sticky problem with timeouts.
If the Responder is down
or otherwise inaccessible, in the worst case we won't hear about this
except by not getting responses.
Some other, more pathological or even
evil, failure cases can have the same result.
The problem is that in the
case where plaintext is permitted, we want to decide whether a tunnel is
possible quickly.
There is no good solution to this, alas;
we just have to take the time and do it right.
(Passing plaintext meanwhile
looks attractive at first glance... but exposing
the first few seconds of a connection is often almost as bad as exposing
the whole thing.
Worse, if the user checks the status of the connection,
after that brief window it looks secure!)
.P
The flip side of waiting for a timeout is that all other forms of
feedback, e.g. ``host not reachable'',
arguably should be \fIignored\fR,
because in the absence of authenticated ICMP,
you cannot trust them!
.R
An alternative, sometimes suggested, to the use of explicit DNS records
for SG discovery is to directly attempt IKE negotiation with the
destination host,
and assume that any relevant SG will be on the packet path,
will intercept the IKE packets,
and will impersonate the destination host for the IKE negotiation.
This is superficially attractive but is a very bad idea.
It assumes that routing is stable throughout negotiation,
that the SG is on the plaintext-packets path,
and that the destination host is routable
(yes, it is possible to have (private) DNS data for an unroutable host).
Playing extra games in the plaintext-packet path hurts performance and
can be expected to be unpopular.
Various difficulties ensue when there are multiple SGs along the path
(there is already bad experience with this, in RSVP),
and the presence of even one can make it impossible
to do IKE direct to the host when that is what's wanted.
Worst of all, such impersonation breaks the IP network model badly,
making problems difficult to diagnose and impossible to work around
(and there is already bad experience with this, in areas like web caching).
.R
(Step 1.)
Dynamic setup actions might include establishment of demand-dialed links.
These might be present anywhere along the path,
so one cannot rely on out-of-band communication at the Initiator to
trigger them.
Hence the ping.
.R
(Step 2.)
In many cases, the IP address on the intercepted packet will be the
result of a name lookup just done.
Inverse queries, an obscure DNS feature from the distant past,
in theory can be used to ask a DNS server to reverse that lookup,
giving the name that produced the address.
This is not the same as a reverse lookup,
and the difference can matter a great deal in cases where a host
does not control its reverse map
(e.g., when the host's IP address is dynamically assigned).
Unfortunately, inverse queries were never widely implemented and
are now considered obsolete.
Phooey.
.A
Support for a small subset of this admittedly-obscure feature
would be useful.
Unfortunately, it seems unlikely.
.R
(Step 3.)
Using only IP addresses to decide whether there is already a relevant
keying channel avoids some
difficult problems.
In particular, it might seem that this should be based on identities,
but those are not known until very late in IKE Phase 1 negotiations.
.R
(Step 4.)
The DNS lookup is done on speculation
because the data will probably be useful and the lookup can be done
in parallel with IKE activity,
potentially speeding things up.
.R
(Steps 7 and 8.)
If an SG does not control its reverse map,
there is no way it can prove its right to use an IP address,
but it can nevertheless supply both an identity (as an FQDN) and
proof of its right to use that identity.
This is somewhat better than nothing,
and may be quite useful if the SG is representing a client host
which \fIcan\fR prove its right to \fIits\fR IP address.
(For example, a fixed-address subnet might live behind an SG with
a dynamically-assigned address;
such an SG has to be the Initiator, not the Responder,
so the subnet's TXT records can contain FQDN identities,
but with that restriction, this works.)
It might sound like this would permit some man-in-the-middle attacks
in important cases like Road Warrior,
but the RW can still do full authentication of the home base,
so a man in the middle cannot successfully impersonate home base,
and the D-H exchange doesn't work unless the man in the middle
impersonates \fIboth\fR ends.
.R
(Steps 7 and 8.)
Another situation where proof of the right to use an identity can be
very useful is when access is deliberately limited.
While opportunistic encryption is intended as a general-purpose
connection mechanism between strangers,
it may well be convenient for prearranged connections to use
the same mechanism.
.R
(Steps 7 and 8.)
FQDNs as identities are avoided where possible,
since they can involve synchronous DNS lookups.
.R
(Step 11.)
Note that only here, in Phase 2,
does the Responder actually learn who the
Source and Destination hosts are.
This unfortunately demands a synchronous DNS lookup to verify that the
Initiator is authorized to represent the Source,
unless they are one and the same.
This and the initial TXT lookup are the only synchronous DNS lookups
absolutely required by the algorithm,
and they appear to be unavoidable.
.R
While it might seem unlikely that a refusal to cooperate from one SG
could be remedied by trying another\(empresumably they all use the
same policies\(emit's conceivable that one might be misconfigured.
Preferably they should all be tried,
but it may be necessary to set some limits on this
if alternatives exist.
.NH 2
DNS Records
.P
Gateway discovery and key lookup are based on TXT and KEY DNS records.
The TXT record specifies IP address or other identity of a host's SG,
and possibly supplies its public key as well,
while the KEY record supplies public keys not found in TXT records.
.NH 3
TXT
.P
Opportunistic-encryption SG discovery uses TXT records with the content:
.DS
X-IPsec-Gateway(\fInnn\fR)=\fIiii\fR\ \fIkkk\fR
.DE
following RFC 1464 attribute/value
notation.
Records which
do not contain an ``='',
or which do not have exactly the specified form to the left of it,
are ignored.
(Near misses perhaps should be reported.)
.P
The \fInnn\fR is an unsigned integer which will fit in 16 bits,
specifying an MX-style preference
(lower number = stronger preference) to
control the order in which multiple SGs are tried.
If there are ties, pick one,
randomly enough that the choice will probably be different each time.
xxx rollover.
The preference field is not optional;
use ``0'' if there is no meaningful preference ordering.
.P
The \fIiii\fR part identifies the SG.
Normally this is a dotted-decimal IPv4 address or
a colon-hex IPv6 address.
The sole exception is if the SG has no fixed address (see 2.4) but
the host(s) behind it do,
in which case \fIiii\fR is of the form ``@fqdn'',
where \fIfqdn\fR is the FQDN that the SG will use to
identify itself (in step 7 of section 2.2);
such a record cannot be used for SG discovery by an Initiator,
but can be used for
SG verification (step 11 of 2.2) by a Responder.
.P
The \fIkkk\fR part is optional.
If it is present,
it is an RSA-MD5 public key in base-64 notation, as in the text
form of an RFC 2535 KEY record.
If it is not present,
this specifies that the public key can be found in a KEY
record located based on the SG's identification:
if \fIiii\fR is an IP address,
do a reverse lookup on that address,
else do a forward lookup on the FQDN.
.R
While it is unusual for a reverse lookup to go for records other than PTR
records (or possibly CNAME records, for RFC 2317 classless delegation),
there's no reason why it can't.
The TXT record is a temporary stand-in
for (we hope, someday) a new DNS record for SG identification and keying.
Keeping the setup process fast requires minimizing the number of DNS
lookups, hence the desire to put all the information in one place.
.R
The use of RFC 1464 notation avoids collisions with other uses of TXT
records.
The ``X-'' in the attribute name
indicates that this format is tentative and experimental;
this design will probably need modification after initial experiments.
The format is chosen with an eye on eventual binary encoding.
Note, in particular,
that the TXT record normally contains the \fIaddress\fR of the SG,
not (repeat, not) its name.
Name-to-address conversion is the job of
whatever generates the TXT record,
which is expected to be a program, not a human\(emthis is conceptually
a \fIbinary\fR record, temporarily using a text encoding.
The ``@fqdn'' form of the SG identity is
for specialized uses and is never mapped to an address.
.A
A DNS TXT record contains one or more character strings,
but RFC 1035 does not describe exactly how
a multi-string TXT record is interpreted.
This is relevant because a string can be at most 255 characters,
and public keys can exceed this.
Empirically, the standard pattern is that
each string which is
both less than 255 characters \fIand\fR not the final string of the
record should have a blank appended to it,
and the strings of the record
should then be concatenated.
(This observation is based on how BIND 8 transforms a TXT record
from text to DNS binary.)
.NH 3
KEY
.P
An opportunistic-encryption KEY record
is an Authentication-permitted,
Entity (host),
non-Signatory,
IPsec,
RSA/MD5 record
(that is, its first four bytes are 0x42000401),
as per RFCs 2535 and 2537.
KEY records with other \fIflags\fR, \fIprotocol\fR, or \fIalgorithm\fR
values are ignored.
.R
Unfortunately, the public key has to be
associated with the SG, not the client host behind it.
The Responder does not know which client it is supposed to be representing,
or which client the Initiator is representing,
until far too late.
.A
Per-client keys would reduce vulnerability to key compromise,
and simplify key changes,
but they would require changes to IKE Phase 1, to separately identify
the SG and its initial client(s).
(At present, the client identities are not known to the Responder
until IKE Phase 2.)
While the current IKE standard does not actually specify (!) who is
being identified by identity payloads,
the overwhelming consensus is that they identify the SG,
and as seen earlier,
this has important uses.
.NH 3
Summary
.P
For reference, the minimum set of DNS records needed to make this
all work is either:
.IP 1. \w'1.'u+2n
TXT in Destination reverse map, identifying Responder and providing public key.
.IP 2.
KEY in Initiator reverse map, providing public key.
.IP 3.
TXT in Source reverse map, verifying relationship to Initiator.
.P
or:
.IP 1. \w'1.'u+2n
TXT in Destination reverse map, identifying Responder.
.IP 2.
KEY in Responder reverse map, providing public key.
.IP 3.
KEY in Initiator reverse map, providing public key.
.IP 4.
TXT in Source reverse map, verifying relationship to Initiator.
.P
Slight complications ensue for dynamic addresses,
lack of control over reverse maps, etc.
.NH 3
Implementation
.P
In the long run, we need either a tree of trust or a web of trust,
so we can trust our DNS data.
The obvious approach for DNS is a tree of trust,
but there are various practical problems with running all of this
through the root servers,
and a web of trust is arguably more robust anyway.
This is logically independent of opportunistic encryption,
and a separate design proposal will be prepared.
.P
Interim stages of implementation of this will require a bit of thought.
Notably, we need some way of dealing with the lack of fully signed DNSSEC
records right away.
Without user interaction, probably the best we can do is to
remember the results of old fetches, compare them to the results of new
fetches, and complain and disbelieve all of it if there's a mismatch. 
This does mean that somebody who gets fake data into our very first fetch
will fool us, at least for a while, but that seems an acceptable tradeoff.
(Obviously there needs to be a way to manually flush the remembered results
for a specific host, to permit deliberate changes.)
.NH 2
Responders Without Credentials
.P
In cases where the Destination simply does not control its
DNS reverse-map entries,
there is no verifiable way to determine a suitable SG.
This does not make communication utterly impossible, though.
.P
Simply attempting negotiation directly with the host is a last resort.
(An aggressive implementation might wish to attempt it in parallel,
rather than waiting until other options are known to be unavailable.)
In particular, in many cases involving dynamic addresses, it will work.
It has the disadvantage of delaying the discovery that opportunistic
encryption is entirely impossible,
but the case seems common enough to justify the overhead.
.P
However, there are policy issues here either way, because
it is possible to impersonate such a host.
The host can supply an FQDN identity and verify its right to use that
identity,
but except by prearrangement,
there is no way to verify that the FQDN is the right one for that
IP address.
(The data from forward lookups may be controlled by people
who do not own the address, so it cannot be trusted.)
The encryption is still solid, though,
so in many cases this may be useful.
.NH 2
Failure of Opportunism
.P
When there is no way to do opportunistic encryption, a policy issue arises:
whether to put in a bypass (which allows plaintext traffic through)
or a block (which discards it, perhaps with notification back to the sender).
The choice is very much a matter of local policy,
and may depend on details such as the higher-level protocol being used.
For example,
an SG might well permit plaintext HTTP but forbid plaintext Telnet,
in which case \fIboth\fR a block and a bypass would be set up if
opportunistic encryption failed.
.P
A bypass/block must, in practice,
be treated much like an IPsec tunnel.
It should persist for a while,
so that high-overhead processing doesn't have to be done for every packet,
but should go away eventually to return resources.
It may be simplest to treat it as a degenerate tunnel.
It should have a relatively long lifetime (say 6h) to keep the frequency
of negotiation attempts down,
except in the case where the other SG simply did not respond to IKE packets,
where the lifetime should be short (say 10min) because
the other SG is presumably down and might come back up again.
(Cases where the other SG responded to IKE with unauthenticated error
reports like ``port unreachable'' are borderline,
and might deserve to be treated as an intermediate case:
while such reports cannot be trusted unreservedly,
in the absence of any other response,
they do give some reason to suspect that the other SG is unable or
unwilling to participate in opportunistic encryption.)
.P
As noted in section 2.1, one might think that
arrival of a plaintext incoming packet should cause a
bypass/block to be set up for its source host:
such a packet is almost always followed by an outgoing reply packet;
the incoming packet is clear evidence that opportunistic encryption is
not available at the other end;
attempting it will waste resources and delay traffic to no good purpose.
Unfortunately, this means that anyone out on the Internet
who can forge a source address can prevent encrypted communication!
Since their source addresses are not authenticated,
plaintext packets cannot be taken as evidence of anything,
except perhaps that communication from that host is likely to occur soon.
.P
There needs to be a way for local administrators to remove a bypass/block
ahead of its normal expiry time,
to force a retry after a problem at the other end is known to have been fixed.
.NH 2
Subnet Opportunism
.P
In principle, when the Source or Destination host belongs to a subnet
and the corresponding SG is willing to provide tunnels to the whole subnet,
this should be done.
There is no extra overhead,
and considerable potential for avoiding later overhead if
similar communication occurs with other members of the subnet.
Unfortunately,
at the moment,
opportunistic tunnels can only have degenerate subnets (single hosts)
at their ends.
(This does, at least, set up the keying channel,
so that negotiations for tunnels to other hosts in the same subnets
will be considerably faster.)
.P
The crucial problem is step 11 of section 2.2:
the Responder must verify that the Initiator is authorized to represent
the Source,
and this is impossible for a subnet because
there is no way to do a reverse lookup on it.
Information in DNS
records for a name or a single address cannot be trusted,
because they may be controlled by people who do not control the whole subnet.
.A
Except in the special case of a subnet masked on a
byte boundary (in which case RFC 1035's convention of an incomplete
in-addr.arpa name could be used), subnet lookup would need extensions to the
reverse-map name space, perhaps along the lines of that commonly done for
RFC 2317 delegation.
IPv6 already has suitable name syntax, as in RFC 2874,
but has no specific provisions for subnet entries in its reverse maps.
Fixing all this is is not conceptually difficult,
but is logically independent of opportunistic encryption,
and will be proposed separately.
.P
A less-troublesome problem is that the Initiator,
in step 10 of 2.2,
must know exactly what subnet is present on the Responder's end
so he can propose a tunnel to it.
This information could be included in the TXT record
of the Destination
(it would have to be verified with a subnet lookup,
but that could be done in parallel with other operations).
The Initiator presumably
can be configured to know what subnet(s) are present on its end.
.NH 2
Option Settings
.P
IPsec and IKE have far too many useless options, and a few useful ones.
IKE negotiation is quite simplistic, and cannot handle even simple
discrepancies between the two SGs.
So it is necessary to be quite specific about what should be done and
what should be proposed,
to guarantee interoperability without prearrangement or
other negotiation protocols.
.R
The prohibition of other negotiations is simply because there is no time.
The setup algorithm (section 2.2) is lengthy already.
.P
[Open question:
should opportunistic IKE use a different port than normal IKE?]
.P
Somewhat arbitrarily and
tentatively, opportunistic SGs must support Main Mode, Oakley group 5 for
D-H, 3DES encryption and MD5 authentication for both ISAKMP and IPsec SAs,
RSA/MD5 digital-signature authentication with keys between 2048 and 8192 bits,
and ESP doing both encryption and authentication.
They must do key PFS
in Quick Mode, but not identity PFS.
They may support IPComp, preferably using Deflate,
but must not insist on it.
They may support AES as an alternative to 3DES,
but must not insist on it.
.R
Identity PFS essentially requires establishing
a complete new keying channel for each new tunnel,
but key PFS just does a new Diffie-Hellman exchange for each rekeying,
which is relatively cheap.
.P
Keying channels must remain in existence at least as long as any
tunnel created with them remains (they are not costly, and keeping
the management path up and available simplifies various issues).
See section 3.1 for related issues.
Given the use of key PFS,
frequent rekeying does not seem critical here.
In the absence of strong reason to do otherwise,
the Initiator should propose rekeying at 8hr-or-1MB.
The Responder must accept any proposal which specifies
a rekeying time between 1hr and 24hr inclusive
and a rekeying volume between 100KB and 10MB inclusive.
.P
Given the short expected useful life of most tunnels (see section 3.1),
very few of them will survive long enough to be rekeyed.
In the absence of strong reason to do otherwise,
the Initiator should propose rekeying at 1hr-or-100MB.
The Responder must accept any proposal which specifies
a rekeying time between 10min and 8hr inclusive
and a rekeying volume between 1MB and 1000MB inclusive.
.P
It is highly desirable to add some random jitter
to the times of actual rekeying attempts,
to break up ``convoys'' of rekeying events;
this and certain other aspects of robust rekeying practice will be the subject
of a separate design proposal.
.R
The numbers used here for rekeying intervals are chosen quite arbitrarily
and should be re-assessed after some implementation experience is gathered.
.NH 1
Renewal and Teardown
.NH 2
Aging
.P
When to tear tunnels down is a bit problematic, but if we're setting up a
potentially unbounded number of them,
we have to tear them down \fIsomehow sometime\fR.
.P
Set a short initial tentative lifespan, say 1min,
since most net flows in fact last only a few seconds.
When that expires, look to see if
the tunnel is still in use (definition:
has had traffic, in either direction,
in the last half of the tentative lifespan).
If so, assign it a somewhat longer tentative lifespan, say 20min,
after which, look again.
If not, close it down.
(This tentative lifespan is
independent of rekeying; it is just the time when the tunnel's future
is next considered.
This should happen reasonably frequently, unlike
rekeying, which is costly and shouldn't be too frequent.)
Multi-step backoff algorithms are not worth the trouble; looking every
20min doesn't seem onerous.
.P
If the security gateway and the client host are one and the same,
tunnel teardown decisions might wish to pay attention to TCP connection status,
as reported by the local TCP layer.
A still-open
TCP connection is almost a guarantee that more traffic is coming, while
the demise of the only TCP connection through a tunnel is a strong hint
that none is.
If the SG and the client host are separate machines,
though, tracking TCP connection status requires packet snooping,
which is complicated and probably not worthwhile.
.P
IKE keying channels likewise are torn down when it appears the need has
passed.
They always linger longer than the last tunnel they administer,
in case they are needed again; the cost of retaining them is low.
Other than that,
unless the number of keying channels on the SG gets large,
the SG should simply retain all of them until rekeying time,
since rekeying is the only costly event.
When about to rekey a keying channel which has no current tunnels,
note when the last actual keying-channel traffic occurred,
and close the keying channel down if it wasn't in the last, say, 30min.
When rekeying a keying channel (or perhaps shortly before rekeying is expected),
Initiator and Responder should re-fetch the public keys used for
SG authentication,
against the possibility that they have changed or disappeared.
.P
See section 2.7 for discussion of rekeying intervals.
.P
Given the low user impact of tearing down and rebuilding a connection
(a tunnel or a keying channel),
rekeying attempts should not be too persistent:
one can always just rebuild when needed,
so heroic efforts to preserve an existing connection are unnecessary.
Say, try every 10s for a minute and every minute for 5min,
and then give up and declare the connection
(and all other connections to that IKE peer) dead.
.R
In future, more sophisticated, versions of this protocol,
examining the initial packet might permit a more intelligent guess at
the tunnel's useful life.
HTTP connections in particular are
notoriously bursty and repetitive.
.R
Note that rekeying a keying connection basically consists of building a
new keying connection from scratch,
using IKE Phase 1,
and abandoning the old one.
.NH 2
Teardown and Cleanup
.P
Teardown should always be coordinated with the other end.
This means interpreting and sending Delete notifications.
.P
On receiving a Delete for the outbound SAs of a tunnel
(or some subset of them),
tear down the inbound ones too, and notify the other end
with a Delete.
Tunnels need to be considered as bidirectional entities,
even though the low-level protocols don't think of them that way.
.P
When the deletion is initiated locally,
rather than as a response to a received Delete,
send a Delete for (all) the inbound SAs of a tunnel.
If no responding Delete is received for the outbound SAs,
try re-sending the original Delete.
Three tries spaced 10s apart seems a reasonable level of effort.
(Indefinite persistence is not necessary;
whether the other end isn't cooperating because it doesn't feel like
it, or because it is down/disconnected/etc.,
the problem will eventually be cleared up by other means.)
.P
After rekeying,
transmission should switch to using the new SAs (ISAKMP or IPsec)
immediately,
and the old leftover SAs should be cleared out promptly
(and Deletes sent) rather than waiting for them to expire.
This reduces clutter and minimizes confusion.
.P
Since there is only one keying channel per remote IP address,
the question of whether a Delete notification has appeared on a
``suitable'' keying channel does not arise.
.R
The pairing of Delete notifications effectively constitutes an
acknowledged Delete, which is highly desirable.
.NH 2
Outages and Reboots
.P
Tunnels sometimes go down because the other
end crashes, or disconnects, or has a network link break,
and there is no notice of this in the general case.
(Even in the event of a crash and
successful reboot, other SGs don't hear about it unless the
rebooted SG has specific reason to talk to them immediately.)
Over-quick response to temporary network outages is undesirable...
but note that a tunnel can be torn
down and then re-established without any user-visible effect except
a pause in traffic,
whereas if one end does reboot,
the other end can't get packets to it \fIat all\fR (except via IKE)
until the situation is noticed.
So a bias toward quick response is appropriate,
even at the cost of occasional false alarms.
.P
Heartbeat mechanisms are somewhat unsatisfactory for this.
Unless they are very frequent, which causes other problems,
they do not detect the problem promptly.
.A
What is really wanted is authenticated ICMP.
This might be a case where public-key encryption/authentication
of network packets is the right thing to do,
despite the expense.
.P
In the absence of that, a two-part approach seems warranted.
.P
First,
when an SG receives an IPsec packet that is addressed to it,
and otherwise appears healthy,
but specifies an unknown SA and is from a host that the receiver currently
has no keying channel to,
the receiver must attempt to inform the sender
via an IKE Initial-Contact notification
(necessarily sent in plaintext,
since there is no suitable keying channel).
This must be severely rate-limited on \fIboth\fR ends;
one notification per SG pair per minute seems ample.
.P
Second, there is an obvious difficulty with this:
the Initial-Contact notification is unauthenticated
and cannot be trusted.
So it must be taken as a hint only:
there must be a way to confirm it.
.P
What is needed here is something that's desirable for
debugging and testing anyway:
an IKE-level ping mechanism.
Pinging direct at the IP level instead will not tell us about a
crash/reboot event.
Sending pings through tunnels has
various complications (they should stop at the far mouth of the tunnel
instead of going on to a subnet; they should not count against idle
timers; etc.).
What is needed is a continuity check on a keying channel.
(This could also be used as a heartbeat,
should that seem useful.)
.P
IKE Ping delivery need not be reliable, since the whole point of a ping is
simply to provoke an acknowledgement.
They should preferably be authenticated,
but it is not clear that this is absolutely necessary,
although if they are not they need
encryption plus a timestamp or a nonce,
to foil replay mischief.
How they are implemented is a secondary issue,
and a separate design proposal will be prepared.
.A
Some existing implementations are already using
(private) notify value 30000 (``LIKE_HELLO'') as ping
and (private) notify value 30002 (``SHUT_UP'') as ping reply.
.P
If an IKE Ping gets no response, try some (say 8) IP pings,
spaced a few seconds apart, to check IP connectivity;
if one comes back, try another IKE Ping;
if that gets no response,
the other end probably has rebooted, or otherwise been re-initialized,
and its tunnels and keying channel(s) should be torn down.
.P
In a similar vein,
giving limited rekeying persistence,
a short network outage could take some tunnels down without
disrupting others.
On receiving a packet for an unknown SA from a host that a keying
channel is currently open to,
send that host a Invalid-SPI notification for that SA.
xxx that's not what Invalid-SPI is for.
The other host can then tear down the half-torn-down tunnel,
and negotiate a new tunnel for the traffic
it presumably still wants to send.
.P
Finally,
it would be helpful if SGs made some attempt to deal intelligently
with crashes and reboots.
A deliberate shutdown should include an attempt to notify all other SGs
currently connected by keying channels,
using Deletes,
that communication is about to fail.
(Again, these will be taken as teardowns;
attempts by the other SGs to negotiate new tunnels as replacements
should be ignored at this point.)
And when possible, SGs should attempt to preserve information
about currently-connected SGs in non-volatile storage, 
so that after a crash,
an Initial-Contact can be sent to previous partners to
indicate loss of all previously-established connections.
.NH 1
Conclusions
.P
This design appears to achieve the objective of setting up encryption
with strangers.
The authentication aspects also seem adequately addressed if the
destination controls its reverse-map DNS entries
and the DNS data itself can be reliably authenticated
as having originated from the legitimate administrators of that
subnet/FQDN.
The authentication situation is less satisfactory when DNS is less helpful,
but it is difficult to see what else could be done about it.
.NH 1
References
.P
[TBW]
.NH 1
Appendix:  Separate Design Proposals TBW
.IP \(bu \w'\(bu'u+2n
How can we build a web of trust with DNSSEC?
(See section 2.3.4.)
.IP \(bu
How can we extend DNS reverse lookups to permit reverse lookup
on a subnet?
(Both address and mask must appear in the name to be looked up.)
(See section 2.6.)
.IP \(bu
How can rekeying be done as robustly as possible?
(At least partly, this is just documenting current FreeS/WAN practice.)
(See section 2.7.)
.IP \(bu
How should IKE Pings be implemented?
(See section 3.3.)
