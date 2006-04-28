








                  Opportunistic Encryption

                       Henry Spencer
                     D. Hugh Redelmeier
                    henry@spsystems.net
                      hugh@mimosa.com
                  Linux FreeS/WAN Project



          Opportunistic   encryption   permits   secure
     (encrypted, authenticated) communication via IPsec
     without  connection-by-connection  prearrangement,
     either explicitly between hosts  (when  the  hosts
     are  capable  of  it) or transparently via packet-
     intercepting  security  gateways.   It  uses   DNS
     records (authenticated with DNSSEC) to provide the
     necessary information for  gateway  discovery  and
     gateway authentication, and constrains negotiation
     enough to guarantee success.

     Substantive  changes  since  draft  3:  write  off
     inverse  queries  as a lost cause; use Invalid-SPI
     rather than Delete as notification of unknown  SA;
     minor  wording  improvements  and  clarifications.
     This document takes over from the  older  ``Imple-
     menting Opportunistic Encryption'' document.


1.  Introduction

A  major  goal  of  the  FreeS/WAN  project is opportunistic
encryption: a  (security)  gateway  intercepts  an  outgoing
packet aimed at a remote host, and quickly attempts to nego-
tiate an IPsec tunnel to that host's security  gateway.   If
the  attempt succeeds, traffic can then be secure, transpar-
ently (without  changes  to  the  host  software).   If  the
attempt  fails,  the  packet  (or  a  retry  thereof) passes
through in clear or is dropped, depending on  local  policy.
Prearranged  tunnels bypass the packet interception etc., so
static VPNs can coexist with opportunistic encryption.

This generalizes trivially to the end-to-end case: host  and
security  gateway  simply  are one and the same.  Some opti-
mizations are possible in that case, but  the  basic  scheme
need not change.

The  objectives  for  security systems need to be explicitly
stated.  Opportunistic encryption is meant to achieve secure
communication, without prearrangement of the individual con-
nection (although some prearrangement on a per-host basis is



Draft 4                  3 May 2001                        1





                  Opportunistic Encryption


required),  between any two hosts which implement the proto-
col (and, if they act as security  gateways,  between  hosts
behind  them).   Here ``secure'' means strong encryption and
authentication of packets, with authentication  of  partici-
pants--to   prevent   man-in-the-middle   and  impersonation
attacks--dependent on several factors.  The  biggest  factor
is  the authentication of DNS records, via DNSSEC or equiva-
lent means.  A lesser factor is which exact variant  of  the
setup  procedure (see section 2.2) is used, because there is
a tradeoff between strong authentication of  the  other  end
and ability to negotiate opportunistic encryption with hosts
which have limited or no control of  their  reverse-map  DNS
records: without reverse-map information, we can verify that
the host has the right to use a particular FQDN (Fully Qual-
ified  Domain Name), but not whether that FQDN is authorized
to use that IP address.  Local policy  must  decide  whether
authentication or connectivity has higher priority.

Apart  from  careful  attention  to detail in various areas,
there are three crucial design  problems  for  opportunistic
encryption.   It  needs a way to quickly identify the remote
host's security gateway.  It needs a way to  quickly  obtain
an  authentication  key  for  the security gateway.  And the
numerous options which can be specified  with  IKE  must  be
constrained  sufficiently  that  two independent implementa-
tions  are  guaranteed  to  reach  agreement,  without   any
explicit  prearrangement  or  preliminary  negotiation.  The
first two problems are solved using DNS, with DNSSEC  ensur-
ing  that the data obtained is reliable; the third is solved
by specifying a minimum standard which must be supported.

A note on philosophy: we have deliberately avoided providing
six  different  ways  to do each job, in favor of specifying
one good one.  Choices are provided only when they appear to
be necessary, or at least important.

A note on terminology: to avoid constant circumlocutions, an
ISAKMP/IKE SA, possibly recreated occasionally by  rekeying,
will  be  referred  to as a ``keying channel'', and a set of
IPsec SAs providing bidirectional communication between  two
IPsec  hosts,  possibly  recreated occasionally by rekeying,
will be referred to as a ``tunnel''  (it  could  conceivably
use transport mode in the host-to-host case, but we advocate
using tunnel mode even there).  The word  ``connection''  is
here  used  in  a more generic sense.  The word ``lifetime''
will be avoided in favor  of  ``rekeying  interval'',  since
many  of  the connections will have useful lives far shorter
than any reasonable rekeying interval,  and  hence  the  two
concepts must be separated.

A note on document structure: Discussions of why things were
done a particular way, or not done  a  particular  way,  are
broken  out in paragraphs headed ``Rationale:'' (to preserve
the flow of the text, many such paragraphs are  deferred  to



Draft 4                  3 May 2001                        2





                  Opportunistic Encryption


the ends of sections).  Paragraphs headed ``Ahem:'' are dis-
cussions of where the problem is  being  made  significantly
harder  by  problems  elsewhere,  and how that might be cor-
rected.  Some meta-comments are enclosed in [].

Rationale: The motive is  to  get  the  Internet  encrypted.
That  requires  encryption  without connection-by-connection
prearrangement: a system must be able to reliably  negotiate
an   encrypted,   authenticated   connection  with  a  total
stranger.  While end-to-end encryption is preferable,  doing
opportunistic encryption in security gateways gives enormous
leverage for quick deployment of this technology, in a world
where  end-host software is often primitive, rigid, and out-
dated.

Rationale: Speed is of the essence in tunnel setup:  a  con-
nection-establishment  delay  longer  than  about 10 seconds
begins to cause problems for users and  applications.   Thus
the emphasis on rapidity in gateway discovery and key fetch-
ing.

Ahem: Host-to-host opportunistic encryption would be utterly
trivial  if a fast public-key encryption/signature algorithm
was available.  You would do a reverse lookup on the  desti-
nation  address to obtain a public key for that address, and
simply encrypt all packets going to it with that key,  sign-
ing them with your own private key.  Alas, this is impracti-
cal with current CPU speeds and current algorithms (although
as  noted  later,  it  might be of some use for limited pur-
poses).  Nevertheless, it is a useful model.

2.  Connection Setup

For purposes of discussion, the network  is  taken  to  look
like this:

     Source----Initiator----...----Responder----Destination

The  intercepted packet comes from the Source, bound for the
Destination, and is intercepted at the Initiator.  The  Ini-
tiator  communicates  over  the  insecure  Internet  to  the
Responder.  The Source and the Initiator might be  the  same
host,  or  the Source might be an end-user host and the Ini-
tiator a security gateway (SG).  Likewise for the  Responder
and the Destination.

Given  an  intercepted packet, whose useful information (for
our purposes)  is  essentially  only  the  Destination's  IP
address,  the Initiator must quickly determine the Responder
(the  Destination's  SG)  and  fetch  everything  needed  to
authenticate  it.   The  Responder  must do likewise for the
Initiator.  Both must eventually also confirm that the other
is  authorized to act on behalf of the client host behind it
(if any).



Draft 4                  3 May 2001                        3





                  Opportunistic Encryption


An important subtlety here is that if the alternative to  an
IPsec  tunnel  is  plaintext  transmission, negative results
must be obtained quickly.  That is,  the  decision  that  no
tunnel can be established must also be made rapidly.

2.1.  Packet Interception

Interception  of outgoing packets is relatively straightfor-
ward in principle.  It is preferable to put the  intercepted
packet  on  hold rather than dropping it, since higher-level
retries are not necessarily well-timed.  There is a  problem
of hosts and applications retrying during negotiations.  ARP
implementations,  which  face  the  same  problem,  use  the
approach  of  keeping  the most recent packet for an as-yet-
unresolved address, and throwing away older  ones.   (Incre-
menting  of request numbers etc. means that replies to older
ones may no longer be accepted.)

Is it worth intercepting incoming packets, from the  outside
world,  and  attempting  tunnel  setup  based  on them?  No,
unless and until a way can be  devised  to  initiate  oppor-
tunistic   encryption   to  a  non-opportunistic  responder,
because if the other end  has  not  initiated  tunnel  setup
itself, it will not be prepared to do so at our request.

Rationale:  Note,  however,  that most incoming packets will
promptly be followed by  an  outgoing  packet  in  response!
Conceivably  it  might  be  useful  to start early stages of
negotiation, at least as far as looking up  information,  in
response to an incoming packet.

Rationale: If a plaintext incoming packet indicates that the
other end is not prepared to do opportunistic encryption, it
might  seem that this fact should be noted, to avoid consum-
ing resources and delaying traffic in an attempt  at  oppor-
tunistic setup which is doomed to fail.  However, this would
be a major security hole, since the plaintext packet is  not
authenticated; see section 2.5.

2.2.  Algorithm

For  clarity,  the following defers most discussion of error
handling to the end.

Step 1.  Initiator does a DNS reverse lookup on the Destina-
         tion address, asking not for the usual PTR records,
         but for TXT  records.   Meanwhile,  Initiator  also
         sends a ping to the Destination, to cause any other
         dynamic setup actions to  start  happening.   (Ping
         replies  are  disregarded;  the  host  might not be
         reachable with plaintext pings.)

Step 2A. If at least one suitable TXT  record  (see  section
         2.3)   comes   back,   each  contains  a  potential



Draft 4                  3 May 2001                        4





                  Opportunistic Encryption


         Responder's IP address and that Responder's  public
         key (or where to find it).  Initiator picks one TXT
         record, based on priority (see 2.3), thus picking a
         Responder.   If  there was no public key in the TXT
         record, the Initiator also starts a DNS lookup  (as
         specified by the TXT record) to get KEY records.

Step 2B. If  no suitable TXT record is available, and policy
         permits,  Initiator  designates   the   Destination
         itself as the Responder (see section 2.4).  If pol-
         icy does not permit, or the  Destination  is  unre-
         sponsive  to  the  negotiation,  then opportunistic
         encryption is not possible, and Initiator gives  up
         (see section 2.5).

Step 3.  If there already is a keying channel to the Respon-
         der's IP address, the Initiator uses  the  existing
         keying  channel;  skip  to step 10.  Otherwise, the
         Initiator starts an IKE Phase  1  negotiation  (see
         section  2.7  for details) with the Responder.  The
         address family of the Responder's IP  address  dic-
         tates whether the keying channel and the outside of
         the tunnel should be IPv4 or IPv6.

Step 4.  Responder gets the first IKE message, and responds.
         It  also starts a DNS reverse lookup on the Initia-
         tor's IP address, for KEY records, on  speculation.

Step 5.  Initiator  gets  Responder's reply, and sends first
         message of IKE's D-H exchange (see 2.4).

Step 6.  Responder  gets  Initiator's   D-H   message,   and
         responds with a matching one.

Step 7.  Initiator  gets Responder's D-H message; encryption
         is now established, authentication  remains  to  be
         done.   Initiator sends IKE authentication message,
         with an FQDN identity if a reverse  lookup  on  its
         address  will  not  yield  a  suitable  KEY record.
         (Note, an FQDN need not actually  correspond  to  a
         host--e.g., the DNS data for it need not include an
         A record.)

Step 8.  Responder gets Initiator's authentication  message.
         If  there  is no identity included, Responder waits
         for step 4's speculative DNS lookup to  finish;  it
         should  yield  a suitable KEY record (see 2.3).  If
         there is an FQDN identity, responder  discards  any
         data obtained from step 4's DNS lookup; does a for-
         ward lookup on the FQDN, for a  KEY  record;  waits
         for  that lookup to return; it should yield a suit-
         able KEY record.  Either way,  Responder  uses  the
         KEY  data  to verify the message's hash.  Responder
         replies with an  authentication  message,  with  an



Draft 4                  3 May 2001                        5





                  Opportunistic Encryption


         FQDN  identity  if  a reverse lookup on its address
         will not yield a suitable KEY record.

Step 9A. (If step 2A was  used.)   The  Initiator  gets  the
         Responder's  authentication  message.   Step 2A has
         provided a key (from the  TXT  record  or  via  DNS
         lookup).   Verify  message's  hash.   Encrypted and
         authenticated keying channel  established,  man-in-
         middle attack precluded.

Step 9B. (If  step  2B  was  used.)   The Initiator gets the
         Responder's authentication message, which must con-
         tain an FQDN identity (if the Responder can't put a
         TXT in his reverse map he presumably can't do a KEY
         either).   Do forward lookup on the FQDN, get suit-
         able KEY record,  verify  hash.   Encrypted  keying
         channel   established,  man-in-middle  attack  pre-
         cluded, but authentication weak (see 2.4).

Step 10. Initiator initiates IKE Phase  2  negotiation  (see
         2.7)  to  establish  tunnel,  specifying Source and
         Destination identities as IP addresses  (see  2.6).
         The  address  family of those addresses also deter-
         mines whether the inside of the  tunnel  should  be
         IPv4 or IPv6.

Step 11. Responder  gets  first  Phase  2  message.  Now the
         Responder finally knows what's  going  on!   Unless
         the specified Source is identical to the Initiator,
         Responder initiates DNS reverse lookup on Source IP
         address,  for  TXT  records; waits for result; gets
         suitable TXT record(s) (see 2.3), which should con-
         tain  either  the Initiator's IP address or an FQDN
         identity identical to that supplied by the  Initia-
         tor in step 7.  This verifies that the Initiator is
         authorized to act as SG for the Source.   Responder
         replies  with  second  Phase  2  message, selecting
         acceptable details (see 2.7), and establishes  tun-
         nel.

Step 12. Initiator  gets second Phase 2 message, establishes
         tunnel (if he didn't  already),  and  releases  the
         intercepted packet into it, finally.

Step 13. Communication  proceeds.   See  section  3 for what
         happens later.

As additional  information  becomes  available,  notably  in
steps 1, 2, 4, 8, 9, 11, and 12, there is always a possibil-
ity that local policy (e.g., access limitations) might  pre-
vent  further progress.  Whenever possible, at least attempt
to inform the other end of this.





Draft 4                  3 May 2001                        6





                  Opportunistic Encryption


At any time, there is a possibility of the negotiation fail-
ing  due  to  unexpected  responses,  e.g. the Responder not
responding at all or rejecting  all  Initiator's  proposals.
If  multiple SGs were found as possible Responders, the Ini-
tiator should try at least one more before giving  up.   The
number  tried  should  be influenced by what the alternative
is: if the traffic will otherwise be discarded,  trying  the
full  list is probably appropriate, while if the alternative
is plaintext transmission, it might be based on how long the
tries  are  taking.   The Initiator should try as many as it
reasonably can, ideally all of them.

There is a sticky problem with timeouts.  If  the  Responder
is  down  or  otherwise  inaccessible,  in the worst case we
won't hear about this except by not getting responses.  Some
other,  more  pathological  or  even evil, failure cases can
have the same result.  The problem is that in the case where
plaintext  is  permitted, we want to decide whether a tunnel
is possible quickly.  There is no  good  solution  to  this,
alas; we just have to take the time and do it right.  (Pass-
ing plaintext meanwhile looks attractive at first  glance...
but  exposing the first few seconds of a connection is often
almost as bad as exposing the whole thing.   Worse,  if  the
user  checks  the status of the connection, after that brief
window it looks secure!)

The flip side of waiting for a timeout  is  that  all  other
forms  of  feedback,  e.g.  ``host not reachable'', arguably
should be ignored, because in the absence  of  authenticated
ICMP, you cannot trust them!

Rationale:  An  alternative, sometimes suggested, to the use
of explicit DNS records for  SG  discovery  is  to  directly
attempt  IKE  negotiation  with  the  destination  host, and
assume that any relevant SG will be on the packet path, will
intercept the IKE packets, and will impersonate the destina-
tion host for the IKE negotiation.   This  is  superficially
attractive  but is a very bad idea.  It assumes that routing
is stable throughout negotiation, that  the  SG  is  on  the
plaintext-packets  path,  and  that  the destination host is
routable (yes, it is possible to have (private) DNS data for
an  unroutable host).  Playing extra games in the plaintext-
packet path hurts performance and  can  be  expected  to  be
unpopular.  Various difficulties ensue when there are multi-
ple SGs along the path (there is already bad experience with
this,  in  RSVP),  and  the presence of even one can make it
impossible to do IKE direct to the host when that is  what's
wanted.  Worst of all, such impersonation breaks the IP net-
work model badly, making problems difficult to diagnose  and
impossible  to work around (and there is already bad experi-
ence with this, in areas like web caching).

Rationale: (Step 1.)  Dynamic setup  actions  might  include
establishment   of  demand-dialed  links.   These  might  be



Draft 4                  3 May 2001                        7





                  Opportunistic Encryption


present anywhere along the path, so one cannot rely on  out-
of-band  communication  at  the  Initiator  to trigger them.
Hence the ping.

Rationale: (Step 2.)  In many cases, the IP address  on  the
intercepted  packet will be the result of a name lookup just
done.  Inverse queries, an obscure DNS feature from the dis-
tant  past,  in  theory  can  be used to ask a DNS server to
reverse that lookup,  giving  the  name  that  produced  the
address.   This is not the same as a reverse lookup, and the
difference can matter a great deal in  cases  where  a  host
does  not  control its reverse map (e.g., when the host's IP
address is dynamically  assigned).   Unfortunately,  inverse
queries were never widely implemented and are now considered
obsolete.  Phooey.

Ahem: Support for a small subset of this  admittedly-obscure
feature  would be useful.  Unfortunately, it seems unlikely.

Rationale: (Step 3.)  Using  only  IP  addresses  to  decide
whether  there  is  already a relevant keying channel avoids
some difficult problems.  In particular, it might seem  that
this  should be based on identities, but those are not known
until very late in IKE Phase 1 negotiations.

Rationale: (Step 4.)  The DNS lookup is done on  speculation
because  the data will probably be useful and the lookup can
be done in parallel with IKE activity, potentially  speeding
things up.

Rationale:  (Steps  7 and 8.)  If an SG does not control its
reverse map, there is no way it can prove its right  to  use
an  IP address, but it can nevertheless supply both an iden-
tity (as an FQDN) and proof of its right to use  that  iden-
tity.   This  is  somewhat  better  than nothing, and may be
quite useful if the SG is representing a client  host  which
can  prove  its  right  to  its IP address.  (For example, a
fixed-address subnet might live behind an SG with a  dynami-
cally-assigned  address; such an SG has to be the Initiator,
not the Responder, so the subnet's TXT records  can  contain
FQDN identities, but with that restriction, this works.)  It
might sound like this would  permit  some  man-in-the-middle
attacks in important cases like Road Warrior, but the RW can
still do full authentication of the home base, so a  man  in
the  middle  cannot  successfully impersonate home base, and
the D-H exchange doesn't work unless the man in  the  middle
impersonates both ends.

Rationale:  (Steps  7 and 8.)  Another situation where proof
of the right to use an identity can be very useful  is  when
access is deliberately limited.  While opportunistic encryp-
tion is intended as a general-purpose  connection  mechanism
between strangers, it may well be convenient for prearranged
connections to use the same mechanism.



Draft 4                  3 May 2001                        8





                  Opportunistic Encryption


Rationale: (Steps 7 and 8.)  FQDNs as identities are avoided
where  possible,  since  they  can  involve  synchronous DNS
lookups.

Rationale: (Step 11.)  Note that only here, in Phase 2, does
the  Responder actually learn who the Source and Destination
hosts are.  This unfortunately  demands  a  synchronous  DNS
lookup  to verify that the Initiator is authorized to repre-
sent the Source, unless they are one and the same.  This and
the  initial TXT lookup are the only synchronous DNS lookups
absolutely required by the algorithm, and they appear to  be
unavoidable.

Rationale:  While  it  might seem unlikely that a refusal to
cooperate from one SG could be remedied by trying  another--
presumably  they all use the same policies--it's conceivable
that one might be misconfigured.  Preferably they should all
be tried, but it may be necessary to set some limits on this
if alternatives exist.

2.3.  DNS Records

Gateway discovery and key lookup are based on  TXT  and  KEY
DNS  records.   The TXT record specifies IP address or other
identity of a host's SG, and possibly  supplies  its  public
key  as  well, while the KEY record supplies public keys not
found in TXT records.

2.3.1.  TXT

Opportunistic-encryption SG discovery uses TXT records  with
the content:

     X-IPsec-Gateway(nnn)=iii kkk

following  RFC 1464 attribute/value notation.  Records which
do not contain an ``='', or which do not  have  exactly  the
specified form to the left of it, are ignored.  (Near misses
perhaps should be reported.)

The nnn is an unsigned integer which will fit  in  16  bits,
specifying  an  MX-style preference (lower number = stronger
preference) to control the order in which multiple  SGs  are
tried.   If  there  are ties, pick one, randomly enough that
the choice will probably be different each time.  The  pref-
erence field is not optional; use ``0'' if there is no mean-
ingful preference ordering.

The iii part identifies the SG.  Normally this is a  dotted-
decimal  IPv4 address or a colon-hex IPv6 address.  The sole
exception is if the SG has no fixed address  (see  2.4)  but
the  host(s)  behind it do, in which case iii is of the form
``@fqdn'', where fqdn is the FQDN that the SG  will  use  to
identify  itself  (in  step 7 of section 2.2); such a record



Draft 4                  3 May 2001                        9





                  Opportunistic Encryption


cannot be used for SG discovery by an Initiator, but can  be
used for SG verification (step 11 of 2.2) by a Responder.

The  kkk  part is optional.  If it is present, it is an RSA-
MD5 public key in base-64 notation, as in the text  form  of
an  RFC  2535 KEY record.  If it is not present, this speci-
fies that the public key  can  be  found  in  a  KEY  record
located  based  on  the SG's identification: if iii is an IP
address, do a reverse lookup on that address, else do a for-
ward lookup on the FQDN.

Rationale:  While  it  is unusual for a reverse lookup to go
for records  other  than  PTR  records  (or  possibly  CNAME
records, for RFC 2317 classless delegation), there's no rea-
son why it can't.  The TXT record is  a  temporary  stand-in
for  (we  hope, someday) a new DNS record for SG identifica-
tion and keying.  Keeping the setup  process  fast  requires
minimizing  the  number  of DNS lookups, hence the desire to
put all the information in one place.

Rationale: The use of RFC 1464  notation  avoids  collisions
with other uses of TXT records.  The ``X-'' in the attribute
name indicates that this format is tentative and  experimen-
tal;  this design will probably need modification after ini-
tial experiments.  The format is chosen with an eye on even-
tual  binary  encoding.   Note,  in particular, that the TXT
record normally contains the address of the SG, not (repeat,
not)  its  name.   Name-to-address  conversion is the job of
whatever generates the TXT record, which is expected to be a
program,  not a human--this is conceptually a binary record,
temporarily using a text encoding.  The  ``@fqdn''  form  of
the  SG identity is for specialized uses and is never mapped
to an address.

Ahem: A DNS  TXT  record  contains  one  or  more  character
strings, but RFC 1035 does not describe exactly how a multi-
string TXT record is interpreted.  This is relevant  because
a  string can be at most 255 characters, and public keys can
exceed this.  Empirically, the standard pattern is that each
string  which  is  both less than 255 characters and not the
final string of the record should have a blank  appended  to
it,  and  the  strings of the record should then be concate-
nated.  (This observation is based on how BIND 8  transforms
a TXT record from text to DNS binary.)

2.3.2.  KEY

An opportunistic-encryption KEY record is an Authentication-
permitted,  Entity  (host),  non-Signatory,  IPsec,  RSA/MD5
record  (that  is,  its first four bytes are 0x42000401), as
per RFCs 2535 and 2537.  KEY records with other flags,  pro-
tocol, or algorithm values are ignored.





Draft 4                  3 May 2001                       10





                  Opportunistic Encryption


Rationale:  Unfortunately,  the public key has to be associ-
ated with the SG,  not  the  client  host  behind  it.   The
Responder  does  not  know which client it is supposed to be
representing, or which client the Initiator is representing,
until far too late.

Ahem: Per-client keys would reduce vulnerability to key com-
promise, and simplify key changes, but  they  would  require
changes  to  IKE  Phase 1, to separately identify the SG and
its initial client(s).  (At present, the  client  identities
are  not  known  to the Responder until IKE Phase 2.)  While
the current IKE standard does not actually specify  (!)  who
is  being  identified by identity payloads, the overwhelming
consensus is that they identify the SG, and as seen earlier,
this has important uses.

2.3.3.  Summary

For reference, the minimum set of DNS records needed to make
this all work is either:

1.  TXT in Destination reverse  map,  identifying  Responder
    and providing public key.

2.  KEY in Initiator reverse map, providing public key.

3.  TXT  in  Source  reverse  map, verifying relationship to
    Initiator.

or:

1.  TXT in Destination reverse map, identifying Responder.

2.  KEY in Responder reverse map, providing public key.

3.  KEY in Initiator reverse map, providing public key.

4.  TXT in Source reverse  map,  verifying  relationship  to
    Initiator.

Slight  complications  ensue  for dynamic addresses, lack of
control over reverse maps, etc.

2.3.4.  Implementation

In the long run, we need either a tree of trust or a web  of
trust,  so  we can trust our DNS data.  The obvious approach
for DNS is a tree of trust, but there are various  practical
problems  with running all of this through the root servers,
and a web of trust is arguably more robust anyway.  This  is
logically  independent  of  opportunistic  encryption, and a
separate design proposal will be prepared.





Draft 4                  3 May 2001                       11





                  Opportunistic Encryption


Interim stages of implementation of this will require a  bit
of  thought.   Notably, we need some way of dealing with the
lack of fully signed DNSSEC  records  right  away.   Without
user interaction, probably the best we can do is to remember
the results of old fetches, compare them to the  results  of
new  fetches,  and  complain  and  disbelieve  all  of it if
there's a mismatch.  This does mean that somebody  who  gets
fake  data  into our very first fetch will fool us, at least
for a while, but that seems an acceptable tradeoff.   (Obvi-
ously  there  needs to be a way to manually flush the remem-
bered results for a  specific  host,  to  permit  deliberate
changes.)

2.4.  Responders Without Credentials

In  cases  where the Destination simply does not control its
DNS reverse-map entries,  there  is  no  verifiable  way  to
determine  a  suitable SG.  This does not make communication
utterly impossible, though.

Simply attempting negotiation directly with the  host  is  a
last  resort.   (An  aggressive implementation might wish to
attempt it in parallel,  rather  than  waiting  until  other
options  are  known  to  be unavailable.)  In particular, in
many cases involving dynamic addresses, it  will  work.   It
has  the  disadvantage of delaying the discovery that oppor-
tunistic encryption is entirely  impossible,  but  the  case
seems common enough to justify the overhead.

However, there are policy issues here either way, because it
is possible to impersonate such a host.  The host can supply
an  FQDN identity and verify its right to use that identity,
but except by prearrangement, there is no way to verify that
the  FQDN  is  the right one for that IP address.  (The data
from forward lookups may be controlled by people who do  not
own  the  address, so it cannot be trusted.)  The encryption
is still solid, though, so in many cases this may be useful.

2.5.  Failure of Opportunism

When  there is no way to do opportunistic encryption, a pol-
icy issue arises: whether to put in a bypass  (which  allows
plaintext  traffic  through)  or a block (which discards it,
perhaps with notification back to the sender).   The  choice
is  very  much  a  matter of local policy, and may depend on
details such as the higher-level protocol being  used.   For
example,  an  SG might well permit plaintext HTTP but forbid
plaintext Telnet, in which case both a block  and  a  bypass
would be set up if opportunistic encryption failed.

A  bypass/block  must,  in practice, be treated much like an
IPsec tunnel.  It should persist for a while, so that  high-
overhead  processing  doesn't  have  to  be  done  for every
packet, but should go away eventually to  return  resources.



Draft 4                  3 May 2001                       12





                  Opportunistic Encryption


It  may  be simplest to treat it as a degenerate tunnel.  It
should have a relatively long lifetime (say 6h) to keep  the
frequency  of  negotiation attempts down, except in the case
where the other SG simply did not respond  to  IKE  packets,
where  the  lifetime should be short (say 10min) because the
other SG is presumably down and might come  back  up  again.
(Cases  where the other SG responded to IKE with unauthenti-
cated error reports like ``port  unreachable''  are  border-
line,  and  might  deserve  to be treated as an intermediate
case: while such reports cannot be trusted unreservedly,  in
the  absence of any other response, they do give some reason
to suspect that the other SG is unable or unwilling to  par-
ticipate in opportunistic encryption.)

As  noted  in section 2.1, one might think that arrival of a
plaintext incoming packet should cause a bypass/block to  be
set  up  for its source host: such a packet is almost always
followed by an outgoing reply packet; the incoming packet is
clear  evidence  that opportunistic encryption is not avail-
able at the other end; attempting it  will  waste  resources
and  delay  traffic to no good purpose.  Unfortunately, this
means that anyone out on the Internet who can forge a source
address  can  prevent  encrypted communication!  Since their
source addresses are not  authenticated,  plaintext  packets
cannot be taken as evidence of anything, except perhaps that
communication from that host is likely to occur soon.

There needs to be a way for local administrators to remove a
bypass/block  ahead  of  its  normal expiry time, to force a
retry after a problem at the other end is known to have been
fixed.

2.6.  Subnet Opportunism

In principle, when the Source or Destination host belongs to
a subnet and the corresponding SG is willing to provide tun-
nels  to the whole subnet, this should be done.  There is no
extra overhead,  and  considerable  potential  for  avoiding
later  overhead  if  similar communication occurs with other
members of the subnet.  Unfortunately, at the moment, oppor-
tunistic  tunnels  can  only have degenerate subnets (single
hosts) at their ends.  (This does, at least, set up the key-
ing channel, so that negotiations for tunnels to other hosts
in the same subnets will be considerably faster.)

The crucial problem is step 11 of section 2.2: the Responder
must  verify  that  the Initiator is authorized to represent
the Source, and this is  impossible  for  a  subnet  because
there  is  no way to do a reverse lookup on it.  Information
in DNS records for a name or  a  single  address  cannot  be
trusted, because they may be controlled by people who do not
control the whole subnet.





Draft 4                  3 May 2001                       13





                  Opportunistic Encryption


Ahem: Except in the special case of a  subnet  masked  on  a
byte  boundary  (in  which  case RFC 1035's convention of an
incomplete in-addr.arpa name could be used),  subnet  lookup
would need extensions to the reverse-map name space, perhaps
along the lines of that commonly done for RFC  2317  delega-
tion.   IPv6  already  has  suitable  name syntax, as in RFC
2874, but has no specific provisions for subnet  entries  in
its  reverse  maps.   Fixing all this is is not conceptually
difficult, but is  logically  independent  of  opportunistic
encryption, and will be proposed separately.

A less-troublesome problem is that the Initiator, in step 10
of 2.2, must know exactly what  subnet  is  present  on  the
Responder's  end  so  he  can  propose a tunnel to it.  This
information could be included in the TXT record of the  Des-
tination (it would have to be verified with a subnet lookup,
but that could be done in parallel with  other  operations).
The Initiator presumably can be configured to know what sub-
net(s) are present on its end.

2.7.  Option Settings

IPsec and IKE have far too many useless options, and  a  few
useful  ones.  IKE negotiation is quite simplistic, and can-
not handle even simple discrepancies between  the  two  SGs.
So it is necessary to be quite specific about what should be
done and what should be proposed,  to  guarantee  interoper-
ability  without  prearrangement or other negotiation proto-
cols.

Rationale: The prohibition of other negotiations  is  simply
because there is no time.  The setup algorithm (section 2.2)
is lengthy already.

[Open question: should opportunistic  IKE  use  a  different
port than normal IKE?]

Somewhat arbitrarily and tentatively, opportunistic SGs must
support Main Mode, Oakley group 5 for D-H,  3DES  encryption
and  MD5  authentication  for  both  ISAKMP  and  IPsec SAs,
RSA/MD5 digital-signature authentication with  keys  between
2048  and  8192  bits,  and  ESP  doing  both encryption and
authentication.  They must do key PFS in Quick Mode, but not
identity  PFS.   They  may  support IPComp, preferably using
Deflate, but must not insist on it.  They may support AES as
an alternative to 3DES, but must not insist on it.

Rationale:  Identity PFS essentially requires establishing a
complete new keying channel for each new tunnel, but key PFS
just  does  a new Diffie-Hellman exchange for each rekeying,
which is relatively cheap.

Keying channels must remain in existence at least as long as
any  tunnel  created with them remains (they are not costly,



Draft 4                  3 May 2001                       14





                  Opportunistic Encryption


and keeping the management path up and available  simplifies
various issues).  See section 3.1 for related issues.  Given
the use of key PFS, frequent rekeying does not seem critical
here.   In the absence of strong reason to do otherwise, the
Initiator  should  propose  rekeying  at  8hr-or-1MB.    The
Responder  must accept any proposal which specifies a rekey-
ing time between 1hr and 24hr inclusive and a rekeying  vol-
ume between 100KB and 10MB inclusive.

Given  the  short  expected useful life of most tunnels (see
section 3.1), very few of them will survive long  enough  to
be  rekeyed.   In  the absence of strong reason to do other-
wise, the Initiator should propose rekeying at 1hr-or-100MB.
The  Responder  must  accept  any proposal which specifies a
rekeying time between 10min and 8hr inclusive and a rekeying
volume between 1MB and 1000MB inclusive.

It  is  highly  desirable  to  add some random jitter to the
times of actual rekeying attempts, to break  up  ``convoys''
of rekeying events; this and certain other aspects of robust
rekeying practice will be the subject of a  separate  design
proposal.

Rationale:  The numbers used here for rekeying intervals are
chosen quite arbitrarily and  should  be  re-assessed  after
some implementation experience is gathered.

3.  Renewal and Teardown

3.1.  Aging

When to tear tunnels down is a bit problematic, but if we're
setting up a potentially unbounded number of them,  we  have
to tear them down somehow sometime.

Set a short initial tentative lifespan, say 1min, since most
net flows in fact  last  only  a  few  seconds.   When  that
expires,  look to see if the tunnel is still in use (defini-
tion: has had traffic, in either direction, in the last half
of  the  tentative  lifespan).   If so, assign it a somewhat
longer tentative lifespan,  say  20min,  after  which,  look
again.   If not, close it down.  (This tentative lifespan is
independent of rekeying; it is just the time when  the  tun-
nel's future is next considered.  This should happen reason-
ably  frequently,  unlike  rekeying,  which  is  costly  and
shouldn't  be  too frequent.)  Multi-step backoff algorithms
are not worth the trouble; looking every 20min doesn't  seem
onerous.

If  the security gateway and the client host are one and the
same, tunnel teardown decisions might wish to pay  attention
to  TCP  connection  status,  as  reported  by the local TCP
layer.  A still-open TCP connection is  almost  a  guarantee
that  more  traffic  is coming, while the demise of the only



Draft 4                  3 May 2001                       15





                  Opportunistic Encryption


TCP connection through a tunnel is a strong hint  that  none
is.   If  the  SG and the client host are separate machines,
though,  tracking  TCP  connection  status  requires  packet
snooping,  which is complicated and probably not worthwhile.

IKE keying channels likewise are torn down when  it  appears
the  need  has  passed.   They always linger longer than the
last tunnel they administer, in case they are needed  again;
the  cost of retaining them is low.  Other than that, unless
the number of keying channels on the SG gets large,  the  SG
should  simply retain all of them until rekeying time, since
rekeying is the only costly event.  When about  to  rekey  a
keying  channel  which has no current tunnels, note when the
last actual keying-channel traffic occurred, and  close  the
keying  channel  down  if it wasn't in the last, say, 30min.
When rekeying a keying channel (or  perhaps  shortly  before
rekeying  is  expected),  Initiator and Responder should re-
fetch the public keys used for  SG  authentication,  against
the possibility that they have changed or disappeared.

See section 2.7 for discussion of rekeying intervals.

Given  the  low user impact of tearing down and rebuilding a
connection (a tunnel or a keying channel), rekeying attempts
should  not  be  too persistent: one can always just rebuild
when needed, so heroic efforts to preserve an existing  con-
nection  are  unnecessary.   Say, try every 10s for a minute
and every minute for 5min, and then give up and declare  the
connection  (and  all  other  connections  to that IKE peer)
dead.

Rationale: In future, more sophisticated, versions  of  this
protocol,  examining  the initial packet might permit a more
intelligent guess at the tunnel's useful life.  HTTP connec-
tions in particular are notoriously bursty and repetitive.

Rationale:  Note that rekeying a keying connection basically
consists of building a new keying connection  from  scratch,
using IKE Phase 1, and abandoning the old one.

3.2.  Teardown and Cleanup

Teardown  should  always  be coordinated with the other end.
This means interpreting and sending Delete notifications.

On receiving a Delete for the outbound SAs of a  tunnel  (or
some  subset  of  them), tear down the inbound ones too, and
notify the other end with a Delete.  Tunnels need to be con-
sidered as bidirectional entities, even though the low-level
protocols don't think of them that way.

When the deletion is initiated locally,  rather  than  as  a
response  to  a received Delete, send a Delete for (all) the
inbound SAs  of  a  tunnel.   If  no  responding  Delete  is



Draft 4                  3 May 2001                       16





                  Opportunistic Encryption


received  for  the outbound SAs, try re-sending the original
Delete.  Three tries spaced 10s  apart  seems  a  reasonable
level  of effort.  (Indefinite persistence is not necessary;
whether the other end isn't cooperating because  it  doesn't
feel  like  it, or because it is down/disconnected/etc., the
problem will eventually be cleared up by other means.)

After rekeying, transmission should switch to using the  new
SAs  (ISAKMP or IPsec) immediately, and the old leftover SAs
should be cleared out promptly  (and  Deletes  sent)  rather
than  waiting  for them to expire.  This reduces clutter and
minimizes confusion.

Since there  is  only  one  keying  channel  per  remote  IP
address,  the  question of whether a Delete notification has
appeared on a ``suitable'' keying channel does not arise.

Rationale: The pairing of Delete  notifications  effectively
constitutes  an  acknowledged Delete, which is highly desir-
able.

3.3.  Outages and Reboots

Tunnels sometimes go down because the other end crashes,  or
disconnects,  or  has  a network link break, and there is no
notice of this in the general case.  (Even in the event of a
crash  and  successful reboot, other SGs don't hear about it
unless the rebooted SG has specific reason to talk  to  them
immediately.)  Over-quick response to temporary network out-
ages is undesirable...  but note that a tunnel can  be  torn
down and then re-established without any user-visible effect
except a pause in traffic, whereas if one end  does  reboot,
the  other  end  can't  get packets to it at all (except via
IKE) until the situation is noticed.  So a bias toward quick
response  is  appropriate,  even  at  the cost of occasional
false alarms.

Heartbeat mechanisms are somewhat unsatisfactory  for  this.
Unless  they are very frequent, which causes other problems,
they do not detect the problem promptly.

Ahem: What is really wanted  is  authenticated  ICMP.   This
might  be  a case where public-key encryption/authentication
of network packets is the right thing  to  do,  despite  the
expense.

In the absence of that, a two-part approach seems warranted.

First, when an SG receives an IPsec packet that is addressed
to  it,  and  otherwise  appears  healthy,  but specifies an
unknown SA and is from a host that  the  receiver  currently
has  no  keying  channel  to,  the  receiver must attempt to
inform the sender via an  IKE  Initial-Contact  notification
(necessarily  sent  in plaintext, since there is no suitable



Draft 4                  3 May 2001                       17





                  Opportunistic Encryption


keying channel).  This must be severely rate-limited on both
ends; one notification per SG pair per minute seems ample.

Second,  there  is an obvious difficulty with this: the Ini-
tial-Contact notification is unauthenticated and  cannot  be
trusted.   So it must be taken as a hint only: there must be
a way to confirm it.

What is needed here is something that's desirable for debug-
ging and testing anyway: an IKE-level ping mechanism.  Ping-
ing direct at the IP level instead will not tell us about  a
crash/reboot event.  Sending pings through tunnels has vari-
ous complications (they should stop at the far mouth of  the
tunnel  instead  of  going  on  to a subnet; they should not
count against idle timers; etc.).  What is needed is a  con-
tinuity check on a keying channel.  (This could also be used
as a heartbeat, should that seem useful.)

IKE Ping delivery need not  be  reliable,  since  the  whole
point  of  a  ping  is simply to provoke an acknowledgement.
They should preferably be authenticated, but it is not clear
that  this is absolutely necessary, although if they are not
they need encryption plus a timestamp or a  nonce,  to  foil
replay  mischief.   How  they are implemented is a secondary
issue, and a separate design proposal will be prepared.

Ahem: Some existing implementations are already using  (pri-
vate)  notify value 30000 (``LIKE_HELLO'') as ping and (pri-
vate) notify value 30002 (``SHUT_UP'') as ping reply.

If an IKE Ping gets no response, try some (say 8) IP  pings,
spaced a few seconds apart, to check IP connectivity; if one
comes back, try another IKE Ping; if that gets no  response,
the  other  end probably has rebooted, or otherwise been re-
initialized, and its tunnels and keying channel(s) should be
torn down.

In  a  similar  vein, giving limited rekeying persistence, a
short network outage could take some  tunnels  down  without
disrupting  others.  On receiving a packet for an unknown SA
from a host that a keying channel is currently open to, send
that host a Invalid-SPI notification for that SA.  The other
host can then tear down the half-torn-down tunnel, and nego-
tiate a new tunnel for the traffic it presumably still wants
to send.

Finally, it would be helpful if SGs  made  some  attempt  to
deal  intelligently  with crashes and reboots.  A deliberate
shutdown should include an attempt to notify all  other  SGs
currently  connected by keying channels, using Deletes, that
communication is about to fail.  (Again, these will be taken
as  teardowns;  attempts  by  the other SGs to negotiate new
tunnels as replacements should be ignored  at  this  point.)
And   when   possible,   SGs   should  attempt  to  preserve



Draft 4                  3 May 2001                       18





                  Opportunistic Encryption


information about currently-connected  SGs  in  non-volatile
storage,  so  that  after a crash, an Initial-Contact can be
sent to previous partners to indicate  loss  of  all  previ-
ously-established connections.

4.  Conclusions

This  design  appears to achieve the objective of setting up
encryption with strangers.  The authentication aspects  also
seem  adequately  addressed  if the destination controls its
reverse-map DNS entries and the DNS data itself can be reli-
ably  authenticated as having originated from the legitimate
administrators of that subnet/FQDN.  The authentication sit-
uation is less satisfactory when DNS is less helpful, but it
is difficult to see what else could be done about it.

5.  References

[TBW]

6.  Appendix:  Separate Design Proposals TBW

o  How can we build a web of trust with DNSSEC?   (See  sec-
   tion 2.3.4.)

o  How  can  we extend DNS reverse lookups to permit reverse
   lookup on a subnet?  (Both address and mask  must  appear
   in the name to be looked up.)  (See section 2.6.)

o  How  can  rekeying  be done as robustly as possible?  (At
   least partly, this is just documenting current  FreeS/WAN
   practice.)  (See section 2.7.)

o  How  should IKE Pings be implemented?  (See section 3.3.)























Draft 4                  3 May 2001                       19


