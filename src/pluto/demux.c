/* demultiplex incoming IKE messages
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/* Ordering Constraints on Payloads
 *
 * rfc2409: The Internet Key Exchange (IKE)
 *
 * 5 Exchanges:
 *   "The SA payload MUST precede all other payloads in a phase 1 exchange."
 *
 *   "Except where otherwise noted, there are no requirements for ISAKMP
 *    payloads in any message to be in any particular order."
 *
 * 5.3 Phase 1 Authenticated With a Revised Mode of Public Key Encryption:
 *
 *   "If the HASH payload is sent it MUST be the first payload of the
 *    second message exchange and MUST be followed by the encrypted
 *    nonce. If the HASH payload is not sent, the first payload of the
 *    second message exchange MUST be the encrypted nonce."
 *
 *   "Save the requirements on the location of the optional HASH payload
 *    and the mandatory nonce payload there are no further payload
 *    requirements. All payloads-- in whatever order-- following the
 *    encrypted nonce MUST be encrypted with Ke_i or Ke_r depending on the
 *    direction."
 *
 * 5.5 Phase 2 - Quick Mode
 *
 *   "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
 *    header and a SA payload MUST immediately follow the HASH."
 *   [NOTE: there may be more than one SA payload, so this is not
 *    totally reasonable.  Probably all SAs should be so constrained.]
 *
 *   "If ISAKMP is acting as a client negotiator on behalf of another
 *    party, the identities of the parties MUST be passed as IDci and
 *    then IDcr."
 *
 *   "With the exception of the HASH, SA, and the optional ID payloads,
 *    there are no payload ordering restrictions on Quick Mode."
 */

/* Unfolding of Identity -- a central mystery
 *
 * This concerns Phase 1 identities, those of the IKE hosts.
 * These are the only ones that are authenticated.  Phase 2
 * identities are for IPsec SAs.
 *
 * There are three case of interest:
 *
 * (1) We initiate, based on a whack command specifying a Connection.
 *     We know the identity of the peer from the Connection.
 *
 * (2) (to be implemented) we initiate based on a flow from our client
 *     to some IP address.
 *     We immediately know one of the peer's client IP addresses from
 *     the flow.  We must use this to figure out the peer's IP address
 *     and Id.  To be solved.
 *
 * (3) We respond to an IKE negotiation.
 *     We immediately know the peer's IP address.
 *     We get an ID Payload in Main I2.
 *
 *     Unfortunately, this is too late for a number of things:
 *     - the ISAKMP SA proposals have already been made (Main I1)
 *       AND one accepted (Main R1)
 *     - the SA includes a specification of the type of ID
 *       authentication so this is negotiated without being told the ID.
 *     - with Preshared Key authentication, Main I2 is encrypted
 *       using the key, so it cannot be decoded to reveal the ID
 *       without knowing (or guessing) which key to use.
 *
 *     There are three reasonable choices here for the responder:
 *     + assume that the initiator is making wise offers since it
 *       knows the IDs involved.  We can balk later (but not gracefully)
 *       when we find the actual initiator ID
 *     + attempt to infer identity by IP address.  Again, we can balk
 *       when the true identity is revealed.  Actually, it is enough
 *       to infer properties of the identity (eg. SA properties and
 *       PSK, if needed).
 *     + make all properties universal so discrimination based on
 *       identity isn't required.  For example, always accept the same
 *       kinds of encryption.  Accept Public Key Id authentication
 *       since the Initiator presumably has our public key and thinks
 *       we must have / can find his.  This approach is weakest
 *       for preshared key since the actual key must be known to
 *       decrypt the Initiator's ID Payload.
 *     These choices can be blended.  For example, a class of Identities
 *     can be inferred, sufficient to select a preshared key but not
 *     sufficient to infer a unique identity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>   /* only used for belt-and-suspenders select call */
#include <sys/poll.h>   /* only used for forensic poll call */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>        /* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>  /* struct iovec */
#endif

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "cookie.h"
#include "connections.h"
#include "state.h"
#include "packet.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "nat_traversal.h"
#include "vendor.h"
#include "modecfg.h"

/* This file does basic header checking and demux of
 * incoming packets.
 */

/* forward declarations */
static bool read_packet(struct msg_digest *md);
static void process_packet(struct msg_digest **mdp);

/* Reply messages are built in this buffer.
 * Only one state transition function can be using it at a time
 * so suspended STFs must save and restore it.
 * It could be an auto variable of complete_state_transition except for the fact
 * that when a suspended STF resumes, its reply message buffer
 * must be at the same location -- there are pointers into it.
 */
u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* state_microcode is a tuple of information parameterizing certain
 * centralized processing of a packet.  For example, it roughly
 * specifies what payloads are expected in this message.
 * The microcode is selected primarily based on the state.
 * In Phase 1, the payload structure often depends on the
 * authentication technique, so that too plays a part in selecting
 * the state_microcode to use.
 */

struct state_microcode {
	enum state_kind state, next_state;
	lset_t flags;
	lset_t req_payloads;        /* required payloads (allows just one) */
	lset_t opt_payloads;        /* optional payloads (any mumber) */
	/* if not ISAKMP_NEXT_NONE, process_packet will emit HDR with this as np */
	u_int8_t first_out_payload;
	enum event_type timeout_event;
	state_transition_fn *processor;
};

/* State Microcode Flags, in several groups */

/* Oakley Auth values: to which auth values does this entry apply?
 * Most entries will use SMF_ALL_AUTH because they apply to all.
 * Note: SMF_ALL_AUTH matches 0 for those circumstances when no auth
 * has been set.
 */
#define SMF_ALL_AUTH    LRANGE(0, OAKLEY_AUTH_ROOF-1)
#define SMF_PSK_AUTH    LELEM(OAKLEY_PRESHARED_KEY)
#define SMF_DS_AUTH     (LELEM(OAKLEY_DSS_SIG)   | LELEM(OAKLEY_RSA_SIG)   | \
						 LELEM(OAKLEY_ECDSA_SIG) | LELEM(OAKLEY_ECDSA_256) | \
						 LELEM(OAKLEY_ECDSA_384) | LELEM(OAKLEY_ECDSA_521))
#define SMF_PKE_AUTH    (LELEM(OAKLEY_RSA_ENC) | LELEM(OAKLEY_ELGAMAL_ENC))
#define SMF_RPKE_AUTH   (LELEM(OAKLEY_RSA_ENC_REV) | LELEM(OAKLEY_ELGAMAL_ENC_REV))

/* misc flags */

#define SMF_INITIATOR   LELEM(OAKLEY_AUTH_ROOF + 0)
#define SMF_FIRST_ENCRYPTED_INPUT       LELEM(OAKLEY_AUTH_ROOF + 1)
#define SMF_INPUT_ENCRYPTED     LELEM(OAKLEY_AUTH_ROOF + 2)
#define SMF_OUTPUT_ENCRYPTED    LELEM(OAKLEY_AUTH_ROOF + 3)
#define SMF_RETRANSMIT_ON_DUPLICATE     LELEM(OAKLEY_AUTH_ROOF + 4)

#define SMF_ENCRYPTED (SMF_INPUT_ENCRYPTED | SMF_OUTPUT_ENCRYPTED)

/* this state generates a reply message */
#define SMF_REPLY   LELEM(OAKLEY_AUTH_ROOF + 5)

/* this state completes P1, so any pending P2 negotiations should start */
#define SMF_RELEASE_PENDING_P2  LELEM(OAKLEY_AUTH_ROOF + 6)

/* end of flags */


static state_transition_fn      /* forward declaration */
	unexpected,
	informational;

/* state_microcode_table is a table of all state_microcode tuples.
 * It must be in order of state (the first element).
 * After initialization, ike_microcode_index[s] points to the
 * first entry in state_microcode_table for state s.
 * Remember that each state name in Main or Quick Mode describes
 * what has happened in the past, not what this message is.
 */

static const struct state_microcode
	*ike_microcode_index[STATE_IKE_ROOF - STATE_IKE_FLOOR];

static const struct state_microcode state_microcode_table[] = {
#define PT(n) ISAKMP_NEXT_##n
#define P(n) LELEM(PT(n))

	/***** Phase 1 Main Mode *****/

	/* No state for main_outI1: --> HDR, SA */

	/* STATE_MAIN_R0: I1 --> R1
	 * HDR, SA --> HDR, SA
	 */
	{ STATE_MAIN_R0, STATE_MAIN_R1
	, SMF_ALL_AUTH | SMF_REPLY
	, P(SA), P(VID) | P(CR), PT(NONE)
	, EVENT_RETRANSMIT, main_inI1_outR1},

	/* STATE_MAIN_I1: R1 --> I2
	 * HDR, SA --> auth dependent
	 * SMF_PSK_AUTH, SMF_DS_AUTH: --> HDR, KE, Ni
	 * SMF_PKE_AUTH:
	 *  --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 * SMF_RPKE_AUTH:
	 *  --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 * Note: since we don't know auth at start, we cannot differentiate
	 * microcode entries based on it.
	 */
	{ STATE_MAIN_I1, STATE_MAIN_I2
	, SMF_ALL_AUTH | SMF_INITIATOR | SMF_REPLY
	, P(SA), P(VID) | P(CR), PT(NONE) /* don't know yet */
	, EVENT_RETRANSMIT, main_inR1_outI2 },

	/* STATE_MAIN_R1: I2 --> R2
	 * SMF_PSK_AUTH, SMF_DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
	 * SMF_PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 *      --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
	 * SMF_RPKE_AUTH:
	 *      HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 *      --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
	 */
	{ STATE_MAIN_R1, STATE_MAIN_R2
	, SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY
	, P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC), PT(KE)
	, EVENT_RETRANSMIT, main_inI2_outR2 },

	{ STATE_MAIN_R1, STATE_UNDEFINED
	, SMF_PKE_AUTH | SMF_REPLY
	, P(KE) | P(ID) | P(NONCE), P(VID) | P(CR) | P(HASH), PT(KE)
	, EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_R1, STATE_UNDEFINED
	, SMF_RPKE_AUTH | SMF_REPLY
	, P(NONCE) | P(KE) | P(ID), P(VID) | P(CR) | P(HASH) | P(CERT), PT(NONCE)
	, EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	/* for states from here on, output message must be encrypted */

	/* STATE_MAIN_I2: R2 --> I3
	 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
	 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
	 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
	 *      --> HDR*, HASH_I
	 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
	 *      --> HDR*, HASH_I
	 */
	{ STATE_MAIN_I2, STATE_MAIN_I3
	, SMF_PSK_AUTH | SMF_DS_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY
	, P(KE) | P(NONCE), P(VID) | P(CR) | P(NATD_RFC), PT(ID)
	, EVENT_RETRANSMIT, main_inR2_outI3 },

	{ STATE_MAIN_I2, STATE_UNDEFINED
	, SMF_PKE_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY
	, P(KE) | P(ID) | P(NONCE), P(VID) | P(CR), PT(HASH)
	, EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	{ STATE_MAIN_I2, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_INITIATOR | SMF_OUTPUT_ENCRYPTED | SMF_REPLY
	, P(NONCE) | P(KE) | P(ID), P(VID) | P(CR), PT(HASH)
	, EVENT_RETRANSMIT, unexpected /* ??? not yet implemented */ },

	/* for states from here on, input message must be encrypted */

	/* STATE_MAIN_R2: I3 --> R3
	 * SMF_PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
	 * SMF_DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
	 */
	{ STATE_MAIN_R2, STATE_MAIN_R3
	, SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
	  | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(ID) | P(HASH), P(VID) | P(CR), PT(NONE)
	, EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_MAIN_R3
	, SMF_DS_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
	  | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(ID) | P(SIG), P(VID) | P(CR) | P(CERT), PT(NONE)
	, EVENT_SA_REPLACE, main_inI3_outR3 },

	{ STATE_MAIN_R2, STATE_UNDEFINED
	, SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED
	  | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(HASH), P(VID) | P(CR), PT(NONE)
	, EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

	/* STATE_MAIN_I3: R3 --> done
	 * SMF_PSK_AUTH: HDR*, IDr1, HASH_R --> done
	 * SMF_DS_AUTH: HDR*, IDr1, [ CERT, ] SIG_R --> done
	 * SMF_PKE_AUTH, SMF_RPKE_AUTH: HDR*, HASH_R --> done
	 * May initiate quick mode by calling quick_outI1
	 */
	{ STATE_MAIN_I3, STATE_MAIN_I4
	, SMF_PSK_AUTH | SMF_INITIATOR
	  | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(ID) | P(HASH), P(VID) | P(CR), PT(NONE)
	, EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_MAIN_I4
	, SMF_DS_AUTH | SMF_INITIATOR
	  | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(ID) | P(SIG), P(VID) | P(CR) | P(CERT), PT(NONE)
	, EVENT_SA_REPLACE, main_inR3 },

	{ STATE_MAIN_I3, STATE_UNDEFINED
	, SMF_PKE_AUTH | SMF_RPKE_AUTH | SMF_INITIATOR
	  | SMF_FIRST_ENCRYPTED_INPUT | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(HASH), P(VID) | P(CR), PT(NONE)
	, EVENT_SA_REPLACE, unexpected /* ??? not yet implemented */ },

	/* STATE_MAIN_R3: can only get here due to packet loss */
	{ STATE_MAIN_R3, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE
	, LEMPTY, LEMPTY
	, PT(NONE), EVENT_NULL, unexpected },

	/* STATE_MAIN_I4: can only get here due to packet loss */
	{ STATE_MAIN_I4, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED
	, LEMPTY, LEMPTY
	, PT(NONE), EVENT_NULL, unexpected },


	/***** Phase 2 Quick Mode *****/

	/* No state for quick_outI1:
	 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
	 */

	/* STATE_QUICK_R0:
	 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
	 * Installs inbound IPsec SAs.
	 * Because it may suspend for asynchronous DNS, first_out_payload
	 * is set to NONE to suppress early emission of HDR*.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_R0, STATE_QUICK_R1
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY
	, P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(NATOA_RFC), PT(NONE)
	, EVENT_RETRANSMIT, quick_inI1_outR1 },

	/* STATE_QUICK_I1:
	 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
	 * HDR*, HASH(3)
	 * Installs inbound and outbound IPsec SAs, routing, etc.
	 * ??? it is legal to have multiple SAs, but we don't support it yet.
	 */
	{ STATE_QUICK_I1, STATE_QUICK_I2
	, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_REPLY
	, P(HASH) | P(SA) | P(NONCE), /* P(SA) | */ P(KE) | P(ID) | P(NATOA_RFC), PT(HASH)
	, EVENT_SA_REPLACE, quick_inR1_outI2 },

	/* STATE_QUICK_R1: HDR*, HASH(3) --> done
	 * Installs outbound IPsec SAs, routing, etc.
	 */
	{ STATE_QUICK_R1, STATE_QUICK_R2
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, P(HASH), LEMPTY, PT(NONE)
	, EVENT_SA_REPLACE, quick_inI2 },

	/* STATE_QUICK_I2: can only happen due to lost packet */
	{ STATE_QUICK_I2, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_INITIATOR | SMF_ENCRYPTED | SMF_RETRANSMIT_ON_DUPLICATE
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

	/* STATE_QUICK_R2: can only happen due to lost packet */
	{ STATE_QUICK_R2, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },


	/***** informational messages *****/

	/* STATE_INFO: */
	{ STATE_INFO, STATE_UNDEFINED
	, SMF_ALL_AUTH
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, informational },

	/* STATE_INFO_PROTECTED: */
	{ STATE_INFO_PROTECTED, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, P(HASH), LEMPTY, PT(NONE)
	, EVENT_NULL, informational },

	/* XAUTH state transitions */
	{ STATE_XAUTH_I0, STATE_XAUTH_I1
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_RETRANSMIT, xauth_inI0 },

	{ STATE_XAUTH_R1, STATE_XAUTH_R2
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_RETRANSMIT, xauth_inR1 },

	{ STATE_XAUTH_I1, STATE_XAUTH_I2
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_SA_REPLACE, xauth_inI1 },

	{ STATE_XAUTH_R2, STATE_XAUTH_R3
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(NONE)
	, EVENT_SA_REPLACE, xauth_inR2 },

	{ STATE_XAUTH_I2, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

	{ STATE_XAUTH_R3, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

	/* ModeCfg pull mode state transitions */

	{ STATE_MODE_CFG_R0, STATE_MODE_CFG_R1
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_SA_REPLACE, modecfg_inR0 },

	{ STATE_MODE_CFG_I1, STATE_MODE_CFG_I2
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_SA_REPLACE, modecfg_inI1 },

	{ STATE_MODE_CFG_R1, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

	{ STATE_MODE_CFG_I2, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

   /* ModeCfg push mode state transitions */

	{ STATE_MODE_CFG_I0, STATE_MODE_CFG_I3
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_SA_REPLACE, modecfg_inI0 },

	{ STATE_MODE_CFG_R3, STATE_MODE_CFG_R4
	, SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_RELEASE_PENDING_P2
	, P(ATTR) | P(HASH), P(VID), PT(HASH)
	, EVENT_SA_REPLACE, modecfg_inR3 },

	{ STATE_MODE_CFG_I3, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

	{ STATE_MODE_CFG_R4, STATE_UNDEFINED
	, SMF_ALL_AUTH | SMF_ENCRYPTED
	, LEMPTY, LEMPTY, PT(NONE)
	, EVENT_NULL, unexpected },

#undef P
#undef PT
};

void
init_demux(void)
{
	/* fill ike_microcode_index:
	 * make ike_microcode_index[s] point to first entry in
	 * state_microcode_table for state s (backward scan makes this easier).
	 * Check that table is in order -- catch coding errors.
	 * For what it's worth, this routine is idempotent.
	 */
	const struct state_microcode *t;

	for (t = &state_microcode_table[countof(state_microcode_table) - 1];;)
	{
		passert(STATE_IKE_FLOOR <= t->state && t->state < STATE_IKE_ROOF);
		ike_microcode_index[t->state - STATE_IKE_FLOOR] = t;
		if (t == state_microcode_table)
			break;
		t--;
		passert(t[0].state <= t[1].state);
	}
}

/* Process any message on the MSG_ERRQUEUE
 *
 * This information is generated because of the IP_RECVERR socket option.
 * The API is sparsely documented, and may be LINUX-only, and only on
 * fairly recent versions at that (hence the conditional compilation).
 *
 * - ip(7) describes IP_RECVERR
 * - recvmsg(2) describes MSG_ERRQUEUE
 * - readv(2) describes iovec
 * - cmsg(3) describes how to process auxiliary messages
 *
 * ??? we should link this message with one we've sent
 * so that the diagnostic can refer to that negotiation.
 *
 * ??? how long can the messge be?
 *
 * ??? poll(2) has a very incomplete description of the POLL* events.
 * We assume that POLLIN, POLLOUT, and POLLERR are all we need to deal with
 * and that POLLERR will be on iff there is a MSG_ERRQUEUE message.
 *
 * We have to code around a couple of surprises:
 *
 * - Select can say that a socket is ready to read from, and
 *   yet a read will hang.  It turns out that a message available on the
 *   MSG_ERRQUEUE will cause select to say something is pending, but
 *   a normal read will hang.  poll(2) can tell when a MSG_ERRQUEUE
 *   message is pending.
 *
 *   This is dealt with by calling check_msg_errqueue after select
 *   has indicated that there is something to read, but before the
 *   read is performed.  check_msg_errqueue will return TRUE if there
 *   is something left to read.
 *
 * - A write to a socket may fail because there is a pending MSG_ERRQUEUE
 *   message, without there being anything wrong with the write.  This
 *   makes for confusing diagnostics.
 *
 *   To avoid this, we call check_msg_errqueue before a write.  True,
 *   there is a race condition (a MSG_ERRQUEUE message might arrive
 *   between the check and the write), but we should eliminate many
 *   of the problematic events.  To narrow the window, the poll(2)
 *   will await until an event happens (in the case or a write,
 *   POLLOUT; this should be benign for POLLIN).
 */

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
static bool
check_msg_errqueue(const struct iface *ifp, short interest)
{
	struct pollfd pfd;

	pfd.fd = ifp->fd;
	pfd.events = interest | POLLPRI | POLLOUT;

	while (pfd.revents = 0
	, poll(&pfd, 1, -1) > 0 && (pfd.revents & POLLERR))
	{
		u_int8_t buffer[3000];  /* hope that this is big enough */
		union
		{
			struct sockaddr sa;
			struct sockaddr_in sa_in4;
			struct sockaddr_in6 sa_in6;
		} from;

		int from_len = sizeof(from);

		int packet_len;

		struct msghdr emh;
		struct iovec eiov;
		union {
			/* force alignment (not documented as necessary) */
			struct cmsghdr ecms;

			/* how much space is enough? */
			unsigned char space[256];
		} ecms_buf;

		struct cmsghdr *cm;
		char fromstr[sizeof(" for message to  port 65536") + INET6_ADDRSTRLEN];
		struct state *sender = NULL;

		zero(&from.sa);
		from_len = sizeof(from);

		emh.msg_name = &from.sa;        /* ??? filled in? */
		emh.msg_namelen = sizeof(from);
		emh.msg_iov = &eiov;
		emh.msg_iovlen = 1;
		emh.msg_control = &ecms_buf;
		emh.msg_controllen = sizeof(ecms_buf);
		emh.msg_flags = 0;

		eiov.iov_base = buffer; /* see readv(2) */
		eiov.iov_len = sizeof(buffer);

		packet_len = recvmsg(ifp->fd, &emh, MSG_ERRQUEUE);

		if (packet_len == -1)
		{
			log_errno((e, "recvmsg(,, MSG_ERRQUEUE) on %s failed in comm_handle"
				, ifp->rname));
			break;
		}
		else if (packet_len == sizeof(buffer))
		{
			plog("MSG_ERRQUEUE message longer than %lu bytes; truncated"
				, (unsigned long) sizeof(buffer));
		}
		else
		{
			sender = find_sender((size_t) packet_len, buffer);
		}

		DBG_cond_dump(DBG_ALL, "rejected packet:\n", buffer, packet_len);
		DBG_cond_dump(DBG_ALL, "control:\n", emh.msg_control, emh.msg_controllen);
		/* ??? Andi Kleen <ak@suse.de> and misc documentation
		 * suggests that name will have the original destination
		 * of the packet.  We seem to see msg_namelen == 0.
		 * Andi says that this is a kernel bug and has fixed it.
		 * Perhaps in 2.2.18/2.4.0.
		 */
		passert(emh.msg_name == &from.sa);
		DBG_cond_dump(DBG_ALL, "name:\n", emh.msg_name
			, emh.msg_namelen);

		fromstr[0] = '\0';      /* usual case :-( */
		switch (from.sa.sa_family)
		{
		char as[INET6_ADDRSTRLEN];

		case AF_INET:
			if (emh.msg_namelen == sizeof(struct sockaddr_in))
				snprintf(fromstr, sizeof(fromstr)
				, " for message to %s port %u"
					, inet_ntop(from.sa.sa_family
					, &from.sa_in4.sin_addr, as, sizeof(as))
					, ntohs(from.sa_in4.sin_port));
			break;
		case AF_INET6:
			if (emh.msg_namelen == sizeof(struct sockaddr_in6))
				snprintf(fromstr, sizeof(fromstr)
					, " for message to %s port %u"
					, inet_ntop(from.sa.sa_family
					, &from.sa_in6.sin6_addr, as, sizeof(as))
					, ntohs(from.sa_in6.sin6_port));
			break;
		}

		for (cm = CMSG_FIRSTHDR(&emh)
		; cm != NULL
		; cm = CMSG_NXTHDR(&emh,cm))
		{
			if (cm->cmsg_level == SOL_IP
			&& cm->cmsg_type == IP_RECVERR)
			{
				/* ip(7) and recvmsg(2) specify:
				 * ee_origin is SO_EE_ORIGIN_ICMP for ICMP
				 *  or SO_EE_ORIGIN_LOCAL for locally generated errors.
				 * ee_type and ee_code are from the ICMP header.
				 * ee_info is the discovered MTU for EMSGSIZE errors
				 * ee_data is not used.
				 *
				 * ??? recvmsg(2) says "SOCK_EE_OFFENDER" but
				 * means "SO_EE_OFFENDER".  The OFFENDER is really
				 * the router that complained.  As such, the port
				 * is meaningless.
				 */

				/* ??? cmsg(3) claims that CMSG_DATA returns
				 * void *, but RFC 2292 and /usr/include/bits/socket.h
				 * say unsigned char *.  The manual is being fixed.
				 */
				struct sock_extended_err *ee = (void *)CMSG_DATA(cm);
				const char *offstr = "unspecified";
				char offstrspace[INET6_ADDRSTRLEN];
				char orname[50];

				if (cm->cmsg_len > CMSG_LEN(sizeof(struct sock_extended_err)))
				{
					const struct sockaddr *offender = SO_EE_OFFENDER(ee);

					switch (offender->sa_family)
					{
					case AF_INET:
						offstr = inet_ntop(offender->sa_family
							, &((const struct sockaddr_in *)offender)->sin_addr
							, offstrspace, sizeof(offstrspace));
						break;
					case AF_INET6:
						offstr = inet_ntop(offender->sa_family
							, &((const struct sockaddr_in6 *)offender)->sin6_addr
							, offstrspace, sizeof(offstrspace));
						break;
					default:
						offstr = "unknown";
						break;
					}
				}

				switch (ee->ee_origin)
				{
				case SO_EE_ORIGIN_NONE:
					snprintf(orname, sizeof(orname), "none");
					break;
				case SO_EE_ORIGIN_LOCAL:
					snprintf(orname, sizeof(orname), "local");
					break;
				case SO_EE_ORIGIN_ICMP:
					snprintf(orname, sizeof(orname)
						, "ICMP type %d code %d (not authenticated)"
						, ee->ee_type, ee->ee_code
						);
					break;
				case SO_EE_ORIGIN_ICMP6:
					snprintf(orname, sizeof(orname)
						, "ICMP6 type %d code %d (not authenticated)"
						, ee->ee_type, ee->ee_code
						);
					break;
				default:
					snprintf(orname, sizeof(orname), "invalid origin %lu"
						, (unsigned long) ee->ee_origin);
					break;
				}

				{
					struct state *old_state = cur_state;

					cur_state = sender;

					/* note dirty trick to suppress ~ at start of format
					 * if we know what state to blame.
					 */
					if ((packet_len == 1) && (buffer[0] == 0xff)
#ifdef DEBUG
						&& ((cur_debugging & DBG_NATT) == 0)
#endif
						) {
							/* don't log NAT-T keepalive related errors unless NATT debug is
							 * enabled
							 */
					}
					else
					plog((sender != NULL) + "~"
						"ERROR: asynchronous network error report on %s"
						"%s"
						", complainant %s"
						": %s"
						" [errno %lu, origin %s"
						/* ", pad %d, info %ld" */
						/* ", data %ld" */
						"]"
						, ifp->rname
						, fromstr
						, offstr
						, strerror(ee->ee_errno)
						, (unsigned long) ee->ee_errno
						, orname
						/* , ee->ee_pad, (unsigned long)ee->ee_info */
						/* , (unsigned long)ee->ee_data */
						);
					cur_state = old_state;
				}
			}
			else
			{
				/* .cmsg_len is a kernel_size_t(!), but the value
				 * certainly ought to fit in an unsigned long.
				 */
				plog("unknown cmsg: level %d, type %d, len %lu"
					, cm->cmsg_level, cm->cmsg_type
					, (unsigned long) cm->cmsg_len);
			}
		}
	}
	return (pfd.revents & interest) != 0;
}
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

bool
send_packet(struct state *st, const char *where)
{
	connection_t *c = st->st_connection;
	int port_buf;
	bool err;
	u_int8_t ike_pkt[MAX_OUTPUT_UDP_SIZE];
	u_int8_t *ptr;
	unsigned long len;

	if (c->interface->ike_float && st->st_tpacket.len != 1)
	{
		if ((unsigned long) st->st_tpacket.len > (MAX_OUTPUT_UDP_SIZE-sizeof(u_int32_t)))
		{
			DBG_log("send_packet(): really too big");
			return FALSE;
		}
		ptr = ike_pkt;
		/** Add Non-ESP marker **/
		memset(ike_pkt, 0, sizeof(u_int32_t));
		memcpy(ike_pkt + sizeof(u_int32_t), st->st_tpacket.ptr,
			(unsigned long)st->st_tpacket.len);
		len = (unsigned long) st->st_tpacket.len + sizeof(u_int32_t);
	}
	else
	{
		ptr = st->st_tpacket.ptr;
		len = (unsigned long) st->st_tpacket.len;
	}

	DBG(DBG_RAW,
		{
			DBG_log("sending %lu bytes for %s through %s to %s:%u:"
				, (unsigned long) st->st_tpacket.len
				, where
				, c->interface->rname
				, ip_str(&c->spd.that.host_addr)
				, (unsigned)c->spd.that.host_port);
			DBG_dump_chunk(NULL, st->st_tpacket);
		});

	/* XXX: Not very clean.  We manipulate the port of the ip_address to
	 * have a port in the sockaddr*, but we retain the original port
	 * and restore it afterwards.
	 */

	port_buf = portof(&c->spd.that.host_addr);
	setportof(htons(c->spd.that.host_port), &c->spd.that.host_addr);

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	(void) check_msg_errqueue(c->interface, POLLOUT);
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

	err = sendto(c->interface->fd
		, ptr, len, 0
		, sockaddrof(&c->spd.that.host_addr)
		, sockaddrlenof(&c->spd.that.host_addr)) != (ssize_t)len;

	/* restore port */
	setportof(port_buf, &c->spd.that.host_addr);

	if (err)
	{
	   /* do not log NAT-T Keep Alive packets */
		if (streq(where, "NAT-T Keep Alive"))
			return FALSE;
		log_errno((e, "sendto on %s to %s:%u failed in %s"
			, c->interface->rname
			, ip_str(&c->spd.that.host_addr)
			, (unsigned)c->spd.that.host_port
			, where));
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

static stf_status
unexpected(struct msg_digest *md)
{
	loglog(RC_LOG_SERIOUS, "unexpected message received in state %s"
		, enum_name(&state_names, md->st->st_state));
	return STF_IGNORE;
}

static stf_status
informational(struct msg_digest *md UNUSED)
{
	struct payload_digest *const n_pld = md->chain[ISAKMP_NEXT_N];

	/* If the Notification Payload is not null... */
	if (n_pld != NULL)
	{
		pb_stream *const n_pbs = &n_pld->pbs;
		struct isakmp_notification *const n = &n_pld->payload.notification;
		int disp_len;
		char disp_buf[200];

		/* Switch on Notification Type (enum) */
		switch (n->isan_type)
		{
		case R_U_THERE:
			return dpd_inI_outR(md->st, n, n_pbs);

		case R_U_THERE_ACK:
			return dpd_inR(md->st, n, n_pbs);
		default:
			if (pbs_left(n_pbs) >= sizeof(disp_buf)-1)
				disp_len = sizeof(disp_buf)-1;
			else
				disp_len = pbs_left(n_pbs);
			memcpy(disp_buf, n_pbs->cur, disp_len);
			disp_buf[disp_len] = '\0';
			break;
		}
	}
	return STF_IGNORE;
}

/* message digest allocation and deallocation */

static struct msg_digest *md_pool = NULL;

/* free_md_pool is only used to avoid leak reports */
void
free_md_pool(void)
{
	for (;;)
	{
		struct msg_digest *md = md_pool;

		if (md == NULL)
			break;
		md_pool = md->next;
		free(md);
	}
}

static struct msg_digest *
malloc_md(void)
{
	struct msg_digest *md = md_pool;

	/* convenient initializer:
	 * - all pointers NULL
	 * - .note = NOTHING_WRONG
	 * - .encrypted = FALSE
	 */
	static const struct msg_digest blank_md = {
		.next = NULL,
	};

	if (md == NULL)
	{
		md = malloc_thing(struct msg_digest);
		zero(md);
	}
	else
		md_pool = md->next;

	*md = blank_md;
	md->digest_roof = md->digest;

	/* note: although there may be multiple msg_digests at once
	 * (due to suspended state transitions), there is a single
	 * global reply_buffer.  It will need to be saved and restored.
	 */
	init_pbs(&md->reply, reply_buffer, sizeof(reply_buffer), "reply packet");

	return md;
}

void
release_md(struct msg_digest *md)
{
	chunk_free(&md->raw_packet);
	free(md->packet_pbs.start);
	md->packet_pbs.start = NULL;
	md->next = md_pool;
	md_pool = md;
}

/* wrapper for read_packet and process_packet
 *
 * The main purpose of this wrapper is to factor out teardown code
 * from the many return points in process_packet.  This amounts to
 * releasing the msg_digest and resetting global variables.
 *
 * When processing of a packet is suspended (STF_SUSPEND),
 * process_packet sets md to NULL to prevent the msg_digest being freed.
 * Someone else must ensure that msg_digest is freed eventually.
 *
 * read_packet is broken out to minimize the lifetime of the
 * enormous input packet buffer, an auto.
 */
void
comm_handle(const struct iface *ifp)
{
	static struct msg_digest *md;

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
	/* Even though select(2) says that there is a message,
	 * it might only be a MSG_ERRQUEUE message.  At least
	 * sometimes that leads to a hanging recvfrom.  To avoid
	 * what appears to be a kernel bug, check_msg_errqueue
	 * uses poll(2) and tells us if there is anything for us
	 * to read.
	 *
	 * This is early enough that teardown isn't required:
	 * just return on failure.
	 */
	if (!check_msg_errqueue(ifp, POLLIN))
		return; /* no normal message to read */
#endif /* defined(IP_RECVERR) && defined(MSG_ERRQUEUE) */

	md = malloc_md();
	md->iface = ifp;

	if (read_packet(md))
		process_packet(&md);

	if (md != NULL)
		release_md(md);

	cur_state = NULL;
	reset_cur_connection();
	cur_from = NULL;
}

/* read the message.
 * Since we don't know its size, we read it into
 * an overly large buffer and then copy it to a
 * new, properly sized buffer.
 */
static bool
read_packet(struct msg_digest *md)
{
	const struct iface *ifp = md->iface;
	int packet_len;
	u_int8_t *buffer;
	u_int8_t *buffer_nat;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in sa_in4;
		struct sockaddr_in6 sa_in6;
	} from;
	int from_len = sizeof(from);
	err_t from_ugh = NULL;
	static const char undisclosed[] = "unknown source";

	happy(anyaddr(addrtypeof(&ifp->addr), &md->sender));
	zero(&from.sa);
	ioctl(ifp->fd, FIONREAD, &packet_len);
	buffer = malloc(packet_len);
	packet_len = recvfrom(ifp->fd, buffer, packet_len, 0
		, &from.sa, &from_len);

	/* First: digest the from address.
	 * We presume that nothing here disturbs errno.
	 */
	if (packet_len == -1
	&& from_len == sizeof(from)
	&& all_zero((const void *)&from.sa, sizeof(from)))
	{
		/* "from" is untouched -- not set by recvfrom */
		from_ugh = undisclosed;
	}
	else if (from_len
	< (int) (offsetof(struct sockaddr, sa_family) + sizeof(from.sa.sa_family)))
	{
		from_ugh = "truncated";
	}
	else
	{
		const struct af_info *afi = aftoinfo(from.sa.sa_family);

		if (afi == NULL)
		{
			from_ugh = "unexpected Address Family";
		}
		else if (from_len != (int)afi->sa_sz)
		{
			from_ugh = "wrong length";
		}
		else
		{
			switch (from.sa.sa_family)
			{
			case AF_INET:
				from_ugh = initaddr((void *) &from.sa_in4.sin_addr
					, sizeof(from.sa_in4.sin_addr), AF_INET, &md->sender);
				md->sender_port = ntohs(from.sa_in4.sin_port);
				break;
			case AF_INET6:
				from_ugh = initaddr((void *) &from.sa_in6.sin6_addr
					, sizeof(from.sa_in6.sin6_addr), AF_INET6, &md->sender);
				md->sender_port = ntohs(from.sa_in6.sin6_port);
				break;
			}
		}
	}

	/* now we report any actual I/O error */
	if (packet_len == -1)
	{
		if (from_ugh == undisclosed
		&& errno == ECONNREFUSED)
		{
			/* Tone down scary message for vague event:
			 * We get "connection refused" in response to some
			 * datagram we sent, but we cannot tell which one.
			 */
			plog("some IKE message we sent has been rejected with ECONNREFUSED (kernel supplied no details)");
		}
		else if (from_ugh != NULL)
		{
			log_errno((e, "recvfrom on %s failed; Pluto cannot decode source sockaddr in rejection: %s"
				, ifp->rname, from_ugh));
		}
		else
		{
			log_errno((e, "recvfrom on %s from %s:%u failed"
				, ifp->rname
				, ip_str(&md->sender), (unsigned)md->sender_port));
		}
		free(buffer);
		return FALSE;
	}
	else if (from_ugh != NULL)
	{
		plog("recvfrom on %s returned malformed source sockaddr: %s"
			, ifp->rname, from_ugh);
		free(buffer);
		return FALSE;
	}
	cur_from = &md->sender;
	cur_from_port = md->sender_port;

	if (ifp->ike_float == TRUE)
	{
		u_int32_t non_esp;

		if (packet_len < (int)sizeof(u_int32_t))
		{
			plog("recvfrom %s:%u too small packet (%d)"
				, ip_str(cur_from), (unsigned) cur_from_port, packet_len);
			free(buffer);
			return FALSE;
		}
		memcpy(&non_esp, buffer, sizeof(u_int32_t));
		if (non_esp != 0)
		{
			plog("recvfrom %s:%u has no Non-ESP marker"
				, ip_str(cur_from), (unsigned) cur_from_port);
			free(buffer);
			return FALSE;
		}
		packet_len -= sizeof(u_int32_t);
		buffer_nat = malloc(packet_len);
		memcpy(buffer_nat, buffer + sizeof(u_int32_t), packet_len);
		free(buffer);
		buffer = buffer_nat;
	}

	/* Clone actual message contents
	 * and set up md->packet_pbs to describe it.
	 */
	init_pbs(&md->packet_pbs, buffer, packet_len, "packet");

	DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL,
		{
			DBG_log(BLANK_FORMAT);
			DBG_log("*received %d bytes from %s:%u on %s"
				, (int) pbs_room(&md->packet_pbs)
				, ip_str(cur_from), (unsigned) cur_from_port
				, ifp->rname);
		});

	DBG(DBG_RAW,
		DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs)));

		if ((pbs_room(&md->packet_pbs)==1) && (md->packet_pbs.start[0]==0xff))
		{
			/**
			 * NAT-T Keep-alive packets should be discarded by kernel ESPinUDP
			 * layer. But bogus keep-alive packets (sent with a non-esp marker)
			 * can reach this point. Complain and discard them.
			 */
			DBG(DBG_NATT,
				DBG_log("NAT-T keep-alive (bogus ?) should not reach this point. "
						"Ignored. Sender: %s:%u", ip_str(cur_from),
						(unsigned) cur_from_port);
			)
			return FALSE;
		}

#define IKEV2_VERSION_OFFSET    17
#define IKEV2_VERSION           0x20

	/* ignore IKEv2 packets - they will be handled by charon */
	if (pbs_room(&md->packet_pbs) > IKEV2_VERSION_OFFSET
	&&  (md->packet_pbs.start[IKEV2_VERSION_OFFSET] & 0xF0) == IKEV2_VERSION)
	{
		DBG(DBG_CONTROLMORE,
			DBG_log("  ignoring IKEv2 packet")
		)
		return FALSE;
	}

	return TRUE;
}

/* process an input packet, possibly generating a reply.
 *
 * If all goes well, this routine eventually calls a state-specific
 * transition function.
 */
static void
process_packet(struct msg_digest **mdp)
{
	struct msg_digest *md = *mdp;
	const struct state_microcode *smc;
	bool new_iv_set = FALSE;
	bool restore_iv = FALSE;
	u_char new_iv[MAX_DIGEST_LEN];
	u_int new_iv_len = 0;

	struct state *st = NULL;
	enum state_kind from_state = STATE_UNDEFINED;       /* state we started in */

#define SEND_NOTIFICATION(t) { \
	if (st) send_notification_from_state(st, from_state, t); \
	else send_notification_from_md(md, t); }

	if (!in_struct(&md->hdr, &isakmp_hdr_desc, &md->packet_pbs, &md->message_pbs))
	{
		/* Identify specific failures:
		 * - bad ISAKMP major/minor version numbers
		 */
		if (md->packet_pbs.roof - md->packet_pbs.cur >= (ptrdiff_t)isakmp_hdr_desc.size)
		{
			struct isakmp_hdr *hdr = (struct isakmp_hdr *)md->packet_pbs.cur;
			if ((hdr->isa_version >> ISA_MAJ_SHIFT) != ISAKMP_MAJOR_VERSION)
			{
				SEND_NOTIFICATION(ISAKMP_INVALID_MAJOR_VERSION);
				return;
			}
			else if ((hdr->isa_version & ISA_MIN_MASK) != ISAKMP_MINOR_VERSION)
			{
				SEND_NOTIFICATION(ISAKMP_INVALID_MINOR_VERSION);
				return;
			}
		}
		SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
		return;
	}

	if (md->packet_pbs.roof != md->message_pbs.roof)
	{
		plog("size (%u) differs from size specified in ISAKMP HDR (%u)"
			, (unsigned) pbs_room(&md->packet_pbs), md->hdr.isa_length);
#ifdef CISCO_QUIRKS
		if (pbs_room(&md->packet_pbs) - md->hdr.isa_length == 16)
			plog("Cisco VPN client appends 16 surplus NULL bytes");
		else
#endif
		return;
	}

	switch (md->hdr.isa_xchg)
	{
#ifdef NOTYET
	case ISAKMP_XCHG_NONE:
	case ISAKMP_XCHG_BASE:
#endif

	case ISAKMP_XCHG_IDPROT:    /* part of a Main Mode exchange */
		if (md->hdr.isa_msgid != MAINMODE_MSGID)
		{
			plog("Message ID was 0x%08lx but should be zero in Main Mode",
				(unsigned long) md->hdr.isa_msgid);
			SEND_NOTIFICATION(ISAKMP_INVALID_MESSAGE_ID);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_icookie))
		{
			plog("Initiator Cookie must not be zero in Main Mode message");
			SEND_NOTIFICATION(ISAKMP_INVALID_COOKIE);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie))
		{
			/* initial message from initiator
			 * ??? what if this is a duplicate of another message?
			 */
			if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
			{
				plog("initial Main Mode message is invalid:"
					" its Encrypted Flag is on");
				SEND_NOTIFICATION(ISAKMP_INVALID_FLAGS);
				return;
			}

			/* don't build a state until the message looks tasty */
			from_state = STATE_MAIN_R0;
		}
		else
		{
			/* not an initial message */

			st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
				, &md->sender, md->hdr.isa_msgid);

			if (st == NULL)
			{
				/* perhaps this is a first message from the responder
				 * and contains a responder cookie that we've not yet seen.
				 */
				st = find_state(md->hdr.isa_icookie, zero_cookie
					, &md->sender, md->hdr.isa_msgid);

				if (st == NULL)
				{
					plog("Main Mode message is part of an unknown exchange");
					/* XXX Could send notification back */
					return;
				}
			}
			set_cur_state(st);
			from_state = st->st_state;
		}
		break;

#ifdef NOTYET
	case ISAKMP_XCHG_AO:
	case ISAKMP_XCHG_AGGR:
#endif

	case ISAKMP_XCHG_INFO:      /* an informational exchange */
		st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
			, &md->sender, MAINMODE_MSGID);

		if (st != NULL)
			set_cur_state(st);

		if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
		{
			if (st == NULL)
			{
				plog("Informational Exchange is for an unknown (expired?) SA");
				/* XXX Could send notification back */
				return;
			}

			if (!IS_ISAKMP_ENCRYPTED(st->st_state))
			{
				loglog(RC_LOG_SERIOUS, "encrypted Informational Exchange message is invalid"
					" because no key is known");
				/* XXX Could send notification back */
				return;
			}

			if (md->hdr.isa_msgid == MAINMODE_MSGID)
			{
				loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
					" it has a Message ID of 0");
				/* XXX Could send notification back */
				return;
			}

			if (!reserve_msgid(st, md->hdr.isa_msgid))
			{
				loglog(RC_LOG_SERIOUS, "Informational Exchange message is invalid because"
					" it has a previously used Message ID (0x%08lx)"
					, (unsigned long)md->hdr.isa_msgid);
				/* XXX Could send notification back */
				return;
			}

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
			{
				memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
				st->st_ph1_iv_len = st->st_new_iv_len;

				/* backup new_iv */
				new_iv_len = st->st_new_iv_len;
				passert(new_iv_len <= MAX_DIGEST_LEN)
				memcpy(new_iv, st->st_new_iv, new_iv_len);
				restore_iv = TRUE;
			}
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_INFO_PROTECTED;
		}
		else
		{
			if (st != NULL && IS_ISAKMP_ENCRYPTED(st->st_state))
			{
				loglog(RC_LOG_SERIOUS, "Informational Exchange message"
					" must be encrypted");
				/* XXX Could send notification back */
				return;
			}
			from_state = STATE_INFO;
		}
		break;

	case ISAKMP_XCHG_QUICK:     /* part of a Quick Mode exchange */
		if (is_zero_cookie(md->hdr.isa_icookie))
		{
			plog("Quick Mode message is invalid because"
				" it has an Initiator Cookie of 0");
			SEND_NOTIFICATION(ISAKMP_INVALID_COOKIE);
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie))
		{
			plog("Quick Mode message is invalid because"
				" it has a Responder Cookie of 0");
			SEND_NOTIFICATION(ISAKMP_INVALID_COOKIE);
			return;
		}

		if (md->hdr.isa_msgid == MAINMODE_MSGID)
		{
			plog("Quick Mode message is invalid because"
				" it has a Message ID of 0");
			SEND_NOTIFICATION(ISAKMP_INVALID_MESSAGE_ID);
			return;
		}

		st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
			, &md->sender, md->hdr.isa_msgid);

		if (st == NULL)
		{
			/* No appropriate Quick Mode state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
				, &md->sender, MAINMODE_MSGID);

			if (st == NULL)
			{
				plog("Quick Mode message is for a non-existent (expired?)"
					" ISAKMP SA");
				/* XXX Could send notification back */
				return;
			}

			set_cur_state(st);

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
			{
				loglog(RC_LOG_SERIOUS, "Quick Mode message is unacceptable because"
					" it is for an incomplete ISAKMP SA");
				SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED /* XXX ? */);
				return;
			}

			/* only accept this new Quick Mode exchange if it has a unique message ID */
			if (!reserve_msgid(st, md->hdr.isa_msgid))
			{
				loglog(RC_LOG_SERIOUS, "Quick Mode I1 message is unacceptable because"
					" it uses a previously used Message ID 0x%08lx"
					" (perhaps this is a duplicated packet)"
					, (unsigned long) md->hdr.isa_msgid);
				SEND_NOTIFICATION(ISAKMP_INVALID_MESSAGE_ID);
				return;
			}

			/* Quick Mode Initial IV */
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			from_state = STATE_QUICK_R0;
		}
		else
		{
			set_cur_state(st);
			from_state = st->st_state;
		}

		break;

	case ISAKMP_XCHG_MODE_CFG:
		if (is_zero_cookie(md->hdr.isa_icookie))
		{
			plog("ModeCfg message is invalid because"
				" it has an Initiator Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (is_zero_cookie(md->hdr.isa_rcookie))
		{
			plog("ModeCfg message is invalid because"
				" it has a Responder Cookie of 0");
			/* XXX Could send notification back */
			return;
		}

		if (md->hdr.isa_msgid == 0)
		{
			plog("ModeCfg message is invalid because"
				" it has a Message ID of 0");
			/* XXX Could send notification back */
			return;
		}

		st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
						, &md->sender, md->hdr.isa_msgid);

		if (st == NULL)
		{
			bool has_xauth_policy;

			/* No appropriate ModeCfg state.
			 * See if we have a Main Mode state.
			 * ??? what if this is a duplicate of another message?
			 */
			st = find_state(md->hdr.isa_icookie, md->hdr.isa_rcookie
							, &md->sender, 0);

			if (st == NULL)
			{
				plog("ModeCfg message is for a non-existent (expired?)"
					" ISAKMP SA");
				/* XXX Could send notification back */
				return;
			}

			set_cur_state(st);

			/* the XAUTH_STATUS message might have a new msgid */
			if (st->st_state == STATE_XAUTH_I1)
			{
				init_phase2_iv(st, &md->hdr.isa_msgid);
				new_iv_set = TRUE;
				from_state = st->st_state;
				break;
			}

			if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
			{
				loglog(RC_LOG_SERIOUS, "ModeCfg message is unacceptable because"
						" it is for an incomplete ISAKMP SA (state=%s)"
						, enum_name(&state_names, st->st_state));
				/* XXX Could send notification back */
				return;
			}
			init_phase2_iv(st, &md->hdr.isa_msgid);
			new_iv_set = TRUE;

			/*
			 * okay, now we have to figure out if we are receiving a bogus
			 * new message in an outstanding XAUTH server conversation
			 * (i.e. a reply to our challenge)
			 * (this occurs with some broken other implementations).
			 *
			 * or if receiving for the first time, an XAUTH challenge.
			 *
			 * or if we are getting a MODECFG request.
			 *
			 * we distinguish these states because we can not both be an
			 * XAUTH server and client, and our policy tells us which
			 * one we are.
			 *
			 * to complicate further, it is normal to start a new msgid
			 * when going from one state to another, or when restarting
			 * the challenge.
			 *
			 */

			has_xauth_policy = (st->st_connection->policy
							   & (POLICY_XAUTH_RSASIG | POLICY_XAUTH_PSK))
							   != LEMPTY;

			if (has_xauth_policy && !st->st_xauth.started
			&& IS_PHASE1(st->st_state))
			{
				from_state = STATE_XAUTH_I0;
			}
			else if (st->st_connection->spd.that.modecfg
			&& IS_PHASE1(st->st_state))
			{
				from_state = STATE_MODE_CFG_R0;
			}
			else if (st->st_connection->spd.this.modecfg
			&& IS_PHASE1(st->st_state))
			{
				from_state = STATE_MODE_CFG_I0;
			}
			else
			{
				/* XXX check if we are being a mode config server here */
				plog("received ModeCfg message when in state %s, and we aren't mode config client"
					 , enum_name(&state_names, st->st_state));
				return;
			}
		}
		else
		{
			set_cur_state(st);
			from_state = st->st_state;
		}
		break;

#ifdef NOTYET
	case ISAKMP_XCHG_NGRP:
	case ISAKMP_XCHG_ACK_INFO:
#endif

	default:
		plog("unsupported exchange type %s in message"
			, enum_show(&exchange_names, md->hdr.isa_xchg));
		SEND_NOTIFICATION(ISAKMP_UNSUPPORTED_EXCHANGE_TYPE);
		return;
	}

	/* We have found a from_state, and perhaps a state object.
	 * If we need to build a new state object,
	 * we wait until the packet has been sanity checked.
	 */

	/* We don't support the Commit Flag.  It is such a bad feature.
	 * It isn't protected -- neither encrypted nor authenticated.
	 * A man in the middle turns it on, leading to DoS.
	 * We just ignore it, with a warning.
	 * By placing the check here, we could easily add a policy bit
	 * to a connection to suppress the warning.  This might be useful
	 * because the Commit Flag is expected from some peers.
	 */
	if (md->hdr.isa_flags & ISAKMP_FLAG_COMMIT)
	{
		plog("IKE message has the Commit Flag set but Pluto doesn't implement this feature; ignoring flag");
	}

	/* Set smc to describe this state's properties.
	 * Look up the appropriate microcode based on state and
	 * possibly Oakley Auth type.
	 */
	passert(STATE_IKE_FLOOR <= from_state && from_state < STATE_IKE_ROOF);
	smc = ike_microcode_index[from_state - STATE_IKE_FLOOR];

	if (st != NULL)
	{
		u_int16_t auth;

		switch (st->st_oakley.auth)
		{
		case XAUTHInitPreShared:
		case XAUTHRespPreShared:
			auth = OAKLEY_PRESHARED_KEY;
			break;
		case XAUTHInitRSA:
		case XAUTHRespRSA:
			auth = OAKLEY_RSA_SIG;
			break;
		default:
			auth = st->st_oakley.auth;
		}

		while (!LHAS(smc->flags, auth))
		{
			smc++;
			passert(smc->state == from_state);
		}
	}

	/* Ignore a packet if the state has a suspended state transition
	 * Probably a duplicated packet but the original packet is not yet
	 * recorded in st->st_rpacket, so duplicate checking won't catch.
	 * ??? Should the packet be recorded earlier to improve diagnosis?
	 */
	if (st != NULL && st->st_suspended_md != NULL)
	{
		loglog(RC_LOG, "discarding packet received during DNS lookup in %s"
			, enum_name(&state_names, st->st_state));
		return;
	}

	/* Detect and handle duplicated packets.
	 * This won't work for the initial packet of an exchange
	 * because we won't have a state object to remember it.
	 * If we are in a non-receiving state (terminal), and the preceding
	 * state did transmit, then the duplicate may indicate that that
	 * transmission wasn't received -- retransmit it.
	 * Otherwise, just discard it.
	 * ??? Notification packets are like exchanges -- I hope that
	 * they are idempotent!
	 */
	if (st != NULL
	&& st->st_rpacket.ptr != NULL
	&& st->st_rpacket.len == pbs_room(&md->packet_pbs)
	&& memeq(st->st_rpacket.ptr, md->packet_pbs.start, st->st_rpacket.len))
	{
		if (smc->flags & SMF_RETRANSMIT_ON_DUPLICATE)
		{
			if (st->st_retransmit < MAXIMUM_RETRANSMISSIONS)
			{
				st->st_retransmit++;
				loglog(RC_RETRANSMISSION
					, "retransmitting in response to duplicate packet; already %s"
					, enum_name(&state_names, st->st_state));
				send_packet(st, "retransmit in response to duplicate");
			}
			else
			{
				loglog(RC_LOG_SERIOUS, "discarding duplicate packet -- exhausted retransmission; already %s"
					, enum_name(&state_names, st->st_state));
			}
		}
		else
		{
			loglog(RC_LOG_SERIOUS, "discarding duplicate packet; already %s"
				, enum_name(&state_names, st->st_state));
		}
		return;
	}

	if (md->hdr.isa_flags & ISAKMP_FLAG_ENCRYPTION)
	{
		DBG(DBG_CRYPT, DBG_log("received encrypted packet from %s:%u"
			, ip_str(&md->sender), (unsigned)md->sender_port));

		if (st == NULL)
		{
			plog("discarding encrypted message for an unknown ISAKMP SA");
			SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED /* XXX ? */);
			return;
		}
		if (st->st_skeyid_e.ptr == (u_char *) NULL)
		{
			loglog(RC_LOG_SERIOUS, "discarding encrypted message"
				" because we haven't yet negotiated keying materiel");
			SEND_NOTIFICATION(ISAKMP_INVALID_FLAGS);
			return;
		}

		/* Mark as encrypted */
		md->encrypted = TRUE;

		DBG(DBG_CRYPT, DBG_log("decrypting %u bytes using algorithm %s"
			, (unsigned) pbs_left(&md->message_pbs)
			, enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

		/* do the specified decryption
		 *
		 * IV is from st->st_iv or (if new_iv_set) st->st_new_iv.
		 * The new IV is placed in st->st_new_iv
		 *
		 * See RFC 2409 "IKE" Appendix B
		 *
		 * XXX The IV should only be updated really if the packet
		 * is successfully processed.
		 * We should keep this value, check for a success return
		 * value from the parsing routines and then replace.
		 *
		 * Each post phase 1 exchange generates IVs from
		 * the last phase 1 block, not the last block sent.
		 */
		{
			size_t crypter_block_size, crypter_iv_size;
			encryption_algorithm_t enc_alg;
			crypter_t *crypter;
			chunk_t data, iv;
		    char *new_iv;

			enc_alg = oakley_to_encryption_algorithm(st->st_oakley.encrypt);
			crypter = lib->crypto->create_crypter(lib->crypto, enc_alg, st->st_enc_key.len);
			crypter_block_size = crypter->get_block_size(crypter);
			crypter_iv_size = crypter->get_iv_size(crypter);

			if (pbs_left(&md->message_pbs) % crypter_block_size != 0)
			{
				loglog(RC_LOG_SERIOUS, "malformed message: not a multiple of encryption blocksize");
				SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
				return;
			}

			/* XXX Detect weak keys */

			/* grab a copy of raw packet (for duplicate packet detection) */
			md->raw_packet = chunk_create(md->packet_pbs.start, pbs_room(&md->packet_pbs));
			md->raw_packet = chunk_clone(md->raw_packet);

			data = chunk_create(md->message_pbs.cur, pbs_left(&md->message_pbs));

			/* Decrypt everything after header */
			if (!new_iv_set)
			{
				/* use old IV */
				passert(st->st_iv_len <= sizeof(st->st_new_iv));
				st->st_new_iv_len = st->st_iv_len;
				memcpy(st->st_new_iv, st->st_iv, st->st_new_iv_len);
			}

			/* form iv by truncation */
			st->st_new_iv_len = crypter_iv_size;
			iv = chunk_create(st->st_new_iv, st->st_new_iv_len);
			new_iv = alloca(crypter_iv_size);
			memcpy(new_iv, data.ptr + data.len - crypter_iv_size,
				   crypter_iv_size);

			crypter->set_key(crypter, st->st_enc_key);
			crypter->decrypt(crypter, data, iv, NULL);
			crypter->destroy(crypter);

			memcpy(st->st_new_iv, new_iv, crypter_iv_size);
			if (restore_iv)
			{
				memcpy(st->st_new_iv, new_iv, new_iv_len);
				st->st_new_iv_len = new_iv_len;
			}
		}

		DBG_cond_dump(DBG_CRYPT, "decrypted:\n", md->message_pbs.cur
			, md->message_pbs.roof - md->message_pbs.cur);

		DBG_cond_dump(DBG_CRYPT, "next IV:"
			, st->st_new_iv, st->st_new_iv_len);
	}
	else
	{
		/* packet was not encryped -- should it have been? */

		if (smc->flags & SMF_INPUT_ENCRYPTED)
		{
			loglog(RC_LOG_SERIOUS, "packet rejected: should have been encrypted");
			SEND_NOTIFICATION(ISAKMP_INVALID_FLAGS);
			return;
		}
	}

	/* Digest the message.
	 * Padding must be removed to make hashing work.
	 * Padding comes from encryption (so this code must be after decryption).
	 * Padding rules are described before the definition of
	 * struct isakmp_hdr in packet.h.
	 */
	{
		struct payload_digest *pd = md->digest;
		int np = md->hdr.isa_np;
		lset_t needed = smc->req_payloads;
		const char *excuse
			= LIN(SMF_PSK_AUTH | SMF_FIRST_ENCRYPTED_INPUT, smc->flags)
				? "probable authentication failure (mismatch of preshared secrets?): "
				: "";

		while (np != ISAKMP_NEXT_NONE)
		{
			struct_desc *sd = np < ISAKMP_NEXT_ROOF? payload_descs[np] : NULL;

			if (pd == &md->digest[PAYLIMIT])
			{
				loglog(RC_LOG_SERIOUS, "more than %d payloads in message; ignored", PAYLIMIT);
				SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
				return;
			}

			switch (np)
			{
				case ISAKMP_NEXT_NATD_RFC:
				case ISAKMP_NEXT_NATOA_RFC:
					if (!st || !(st->nat_traversal & NAT_T_WITH_RFC_VALUES))
					{
						/*
						 * don't accept NAT-D/NAT-OA reloc directly in message, unless
						 * we're using NAT-T RFC
						 */
						sd = NULL;
					}
					break;
			}

			if (sd == NULL)
			{
				/* payload type is out of range or requires special handling */
				switch (np)
				{
				case ISAKMP_NEXT_ID:
					sd = IS_PHASE1(from_state)
						? &isakmp_identification_desc : &isakmp_ipsec_identification_desc;
					break;
				case ISAKMP_NEXT_NATD_DRAFTS:
					np = ISAKMP_NEXT_NATD_RFC;  /* NAT-D relocated */
					sd = payload_descs[np];
					break;
				case ISAKMP_NEXT_NATOA_DRAFTS:
					np = ISAKMP_NEXT_NATOA_RFC;  /* NAT-OA relocated */
					sd = payload_descs[np];
					break;
				default:
					loglog(RC_LOG_SERIOUS, "%smessage ignored because it contains an unknown or"
						" unexpected payload type (%s) at the outermost level"
						, excuse, enum_show(&payload_names, np));
					SEND_NOTIFICATION(ISAKMP_INVALID_PAYLOAD_TYPE);
					return;
				}
			}

			{
				lset_t s = LELEM(np);

				if (LDISJOINT(s
				, needed | smc->opt_payloads| LELEM(ISAKMP_NEXT_N) | LELEM(ISAKMP_NEXT_D)))
				{
					loglog(RC_LOG_SERIOUS, "%smessage ignored because it "
						   "contains an unexpected payload type (%s)"
						, excuse, enum_show(&payload_names, np));
					SEND_NOTIFICATION(ISAKMP_INVALID_PAYLOAD_TYPE);
					return;
				}
				needed &= ~s;
			}

			if (!in_struct(&pd->payload, sd, &md->message_pbs, &pd->pbs))
			{
				loglog(RC_LOG_SERIOUS, "%smalformed payload in packet", excuse);
				if (md->hdr.isa_xchg != ISAKMP_XCHG_INFO)
					SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
				return;
			}

			/* place this payload at the end of the chain for this type */
			{
				struct payload_digest **p;

				for (p = &md->chain[np]; *p != NULL; p = &(*p)->next)
					;
				*p = pd;
				pd->next = NULL;
			}

			np = pd->payload.generic.isag_np;
			pd++;

			/* since we've digested one payload happily, it is probably
			 * the case that any decryption worked.  So we will not suggest
			 * encryption failure as an excuse for subsequent payload
			 * problems.
			 */
			excuse = "";
		}

		md->digest_roof = pd;

		DBG(DBG_PARSING,
			if (pbs_left(&md->message_pbs) != 0)
				DBG_log("removing %d bytes of padding", (int) pbs_left(&md->message_pbs)));

		md->message_pbs.roof = md->message_pbs.cur;

		/* check that all mandatory payloads appeared */

		if (needed != 0)
		{
			loglog(RC_LOG_SERIOUS, "message for %s is missing payloads %s"
				, enum_show(&state_names, from_state)
				, bitnamesof(payload_name, needed));
			SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
			return;
		}
	}

	/* more sanity checking: enforce most ordering constraints */

	if (IS_PHASE1(from_state))
	{
		/* rfc2409: The Internet Key Exchange (IKE), 5 Exchanges:
		 * "The SA payload MUST precede all other payloads in a phase 1 exchange."
		 */
		if (md->chain[ISAKMP_NEXT_SA] != NULL
		&& md->hdr.isa_np != ISAKMP_NEXT_SA)
		{
			loglog(RC_LOG_SERIOUS, "malformed Phase 1 message: does not start with an SA payload");
			SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
			return;
		}
	}
	else if (IS_QUICK(from_state))
	{
		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode
		 *
		 * "In Quick Mode, a HASH payload MUST immediately follow the ISAKMP
		 *  header and a SA payload MUST immediately follow the HASH."
		 * [NOTE: there may be more than one SA payload, so this is not
		 *  totally reasonable.  Probably all SAs should be so constrained.]
		 *
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 *
		 * "With the exception of the HASH, SA, and the optional ID payloads,
		 *  there are no payload ordering restrictions on Quick Mode."
		 */

		if (md->hdr.isa_np != ISAKMP_NEXT_HASH)
		{
			loglog(RC_LOG_SERIOUS, "malformed Quick Mode message: does not start with a HASH payload");
			SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
			return;
		}

		{
			struct payload_digest *p;
			int i;

			for (p = md->chain[ISAKMP_NEXT_SA], i = 1; p != NULL
			; p = p->next, i++)
			{
				if (p != &md->digest[i])
				{
					loglog(RC_LOG_SERIOUS, "malformed Quick Mode message: SA payload is in wrong position");
					SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
					return;
				}
			}
		}

		/* rfc2409: The Internet Key Exchange (IKE), 5.5 Phase 2 - Quick Mode:
		 * "If ISAKMP is acting as a client negotiator on behalf of another
		 *  party, the identities of the parties MUST be passed as IDci and
		 *  then IDcr."
		 */
		{
			struct payload_digest *id = md->chain[ISAKMP_NEXT_ID];

			if (id != NULL)
			{
				if (id->next == NULL || id->next->next != NULL)
				{
					loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
						" if any ID payload is present,"
						" there must be exactly two");
					SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
					return;
				}
				if (id+1 != id->next)
				{
					loglog(RC_LOG_SERIOUS, "malformed Quick Mode message:"
						" the ID payloads are not adjacent");
					SEND_NOTIFICATION(ISAKMP_PAYLOAD_MALFORMED);
					return;
				}
			}
		}
	}

	/* Ignore payloads that we don't handle:
	 * Delete, Notification, VendorID
	 */
	/* XXX Handle deletions */
	/* XXX Handle Notifications */
	/* XXX Handle VID payloads */
	{
		struct payload_digest *p;

		for (p = md->chain[ISAKMP_NEXT_N]; p != NULL; p = p->next)
		{
			if (p->payload.notification.isan_type != R_U_THERE
			&&  p->payload.notification.isan_type != R_U_THERE_ACK)
			{
				loglog(RC_LOG_SERIOUS, "ignoring informational payload, type %s"
					, enum_show(&notification_names, p->payload.notification.isan_type));
			}
			DBG_cond_dump(DBG_PARSING, "info:", p->pbs.cur, pbs_left(&p->pbs));
		}

		for (p = md->chain[ISAKMP_NEXT_D]; p != NULL; p = p->next)
		{
			accept_delete(st, md, p);
			DBG_cond_dump(DBG_PARSING, "del:", p->pbs.cur, pbs_left(&p->pbs));
		}

		for (p = md->chain[ISAKMP_NEXT_VID]; p != NULL; p = p->next)
		{
			handle_vendorid(md, p->pbs.cur, pbs_left(&p->pbs));
		}
	}
	md->from_state = from_state;
	md->smc = smc;
	md->st = st;

	/* possibly fill in hdr */
	if (smc->first_out_payload != ISAKMP_NEXT_NONE)
		echo_hdr(md, (smc->flags & SMF_OUTPUT_ENCRYPTED) != 0
			, smc->first_out_payload);

	complete_state_transition(mdp, smc->processor(md));
}

/* complete job started by the state-specific state transition function */

void
complete_state_transition(struct msg_digest **mdp, stf_status result)
{
	bool has_xauth_policy;
	bool is_xauth_server;
	struct msg_digest *md = *mdp;
	const struct state_microcode *smc = md->smc;
	enum state_kind from_state = md->from_state;
	struct state *st;

	cur_state = st = md->st;    /* might have changed */

	/* If state has DPD support, import it */
	if (st && md->dpd)
		st->st_dpd = TRUE;

	switch (result)
	{
		case STF_IGNORE:
			break;

		case STF_SUSPEND:
			/* the stf didn't complete its job: don't relase md */
			*mdp = NULL;
			break;

		case STF_OK:
			/* advance the state */
			st->st_state = smc->next_state;

			/* Delete previous retransmission event.
			 * New event will be scheduled below.
			 */
			delete_event(st);

			/* replace previous receive packet with latest */

			free(st->st_rpacket.ptr);

			if (md->encrypted)
			{
				/* if encrypted, duplication already done */
				st->st_rpacket = md->raw_packet;
				md->raw_packet.ptr = NULL;
			}
			else
			{
				st->st_rpacket = chunk_create(md->packet_pbs.start,
											  pbs_room(&md->packet_pbs));
				st->st_rpacket = chunk_clone(st->st_rpacket);
			}

			/* free previous transmit packet */
			chunk_free(&st->st_tpacket);

			/* if requested, send the new reply packet */
			if (smc->flags & SMF_REPLY)
			{
				close_output_pbs(&md->reply);   /* good form, but actually a no-op */

				st->st_tpacket = chunk_create(md->reply.start, pbs_offset(&md->reply));
				st->st_tpacket = chunk_clone(st->st_tpacket);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md, md->st);

				/* actually send the packet
				 * Note: this is a great place to implement "impairments"
				 * for testing purposes.  Suppress or duplicate the
				 * send_packet call depending on st->st_state.
				 */
				send_packet(st, enum_name(&state_names, from_state));
			}

			/* Schedule for whatever timeout is specified */
			{
				time_t delay = UNDEFINED_TIME;
				enum event_type kind = smc->timeout_event;
				bool agreed_time = FALSE;
				connection_t *c = st->st_connection;

				switch (kind)
				{
				case EVENT_RETRANSMIT:  /* Retransmit packet */
					delay = EVENT_RETRANSMIT_DELAY_0;
					break;

				case EVENT_SA_REPLACE:  /* SA replacement event */
					if (IS_PHASE1(st->st_state))
					{
						/* Note: we will defer to the "negotiated" (dictated)
						 * lifetime if we are POLICY_DONT_REKEY.
						 * This allows the other side to dictate
						 * a time we would not otherwise accept
						 * but it prevents us from having to initiate
						 * rekeying.  The negative consequences seem
						 * minor.
						 */
						delay = c->sa_ike_life_seconds;
						if ((c->policy & POLICY_DONT_REKEY)
						|| delay >= st->st_oakley.life_seconds)
						{
							agreed_time = TRUE;
							delay = st->st_oakley.life_seconds;
						}
					}
					else
					{
						/* Delay is min of up to four things:
						 * each can limit the lifetime.
						 */
						delay = c->sa_ipsec_life_seconds;
						if (st->st_ah.present
						&& delay >= st->st_ah.attrs.life_seconds)
						{
							agreed_time = TRUE;
							delay = st->st_ah.attrs.life_seconds;
						}
						if (st->st_esp.present
						&& delay >= st->st_esp.attrs.life_seconds)
						{
							agreed_time = TRUE;
							delay = st->st_esp.attrs.life_seconds;
						}
						if (st->st_ipcomp.present
						&& delay >= st->st_ipcomp.attrs.life_seconds)
						{
							agreed_time = TRUE;
							delay = st->st_ipcomp.attrs.life_seconds;
						}
					}

					/* By default, we plan to rekey.
					 *
					 * If there isn't enough time to rekey, plan to
					 * expire.
					 *
					 * If we are --dontrekey, a lot more rules apply.
					 * If we are the Initiator, use REPLACE_IF_USED.
					 * If we are the Responder, and the dictated time
					 * was unacceptable (too large), plan to REPLACE
					 * (the only way to ratchet down the time).
					 * If we are the Responder, and the dictated time
					 * is acceptable, plan to EXPIRE.
					 *
					 * Important policy lies buried here.
					 * For example, we favour the initiator over the
					 * responder by making the initiator start rekeying
					 * sooner.  Also, fuzz is only added to the
					 * initiator's margin.
					 *
					 * Note: for ISAKMP SA, we let the negotiated
					 * time stand (implemented by earlier logic).
					 */
					if (agreed_time
					&& (c->policy & POLICY_DONT_REKEY))
					{
						kind = (smc->flags & SMF_INITIATOR)
							? EVENT_SA_REPLACE_IF_USED
							: EVENT_SA_EXPIRE;
					}
					if (kind != EVENT_SA_EXPIRE)
					{
						unsigned long marg = c->sa_rekey_margin;

						if (smc->flags & SMF_INITIATOR)
							marg += marg
								* c->sa_rekey_fuzz / 100.E0
								* (rand() / (RAND_MAX + 1.E0));
						else
							marg /= 2;

						if ((unsigned long)delay > marg)
						{
							delay -= marg;
							st->st_margin = marg;
						}
						else
						{
							kind = EVENT_SA_EXPIRE;
						}
					}
					break;

				case EVENT_NULL:                /* non-event */
				case EVENT_REINIT_SECRET:       /* Refresh cookie secret */
				default:
					bad_case(kind);
				}
				event_schedule(kind, delay, st);
			}

			/* tell whack and log of progress */
			{
				const char *story = state_story[st->st_state];
				enum rc_type w = RC_NEW_STATE + st->st_state;
				char sadetails[128];

				sadetails[0]='\0';

				if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
				{
					char *b = sadetails;
					const char *ini = " {";
					const char *fin = "";

					/* -1 is to leave space for "fin" */

					if (st->st_esp.present)
					{
						snprintf(b, sizeof(sadetails)-(b-sadetails)-1
								 , "%sESP=>0x%08x <0x%08x"
								 , ini
								 , ntohl(st->st_esp.attrs.spi)
								 , ntohl(st->st_esp.our_spi));
						ini = " ";
						fin = "}";
					}
					/* advance b to end of string */
					b = b + strlen(b);

					if (st->st_ah.present)
					{
						snprintf(b, sizeof(sadetails)-(b-sadetails)-1
								 , "%sAH=>0x%08x <0x%08x"
								 , ini
								 , ntohl(st->st_ah.attrs.spi)
								 , ntohl(st->st_ah.our_spi));
						ini = " ";
						fin = "}";
					}
					/* advance b to end of string */
					b = b + strlen(b);

					if (st->st_ipcomp.present)
					{
						snprintf(b, sizeof(sadetails)-(b-sadetails)-1
								 , "%sIPCOMP=>0x%08x <0x%08x"
								 , ini
								 , ntohl(st->st_ipcomp.attrs.spi)
								 , ntohl(st->st_ipcomp.our_spi));
						ini = " ";
						fin = "}";
					}
					/* advance b to end of string */
					b = b + strlen(b);

					if (st->nat_traversal)
					{
						char oa[ADDRTOT_BUF];
						addrtot(&st->nat_oa, 0, oa, sizeof(oa));
						snprintf(b, sizeof(sadetails)-(b-sadetails)-1
								 , "%sNATOA=%s"
								 , ini, oa);
						ini = " ";
						fin = "}";
					}

					/* advance b to end of string */
					b = b + strlen(b);

					if (st->st_dpd)
					{
						snprintf(b, sizeof(sadetails)-(b-sadetails)-1
								 , "%sDPD"
								 , ini);
						ini = " ";
						fin = "}";
					}

					strcat(b, fin);
				}

				if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)
				||  IS_IPSEC_SA_ESTABLISHED(st->st_state))
				{
					/* log our success */
					plog("%s%s", story, sadetails);
					w = RC_SUCCESS;
				}

				/* tell whack our progress */
				whack_log(w
					, "%s: %s%s"
					, enum_name(&state_names, st->st_state)
					, story, sadetails);
			}

			has_xauth_policy = (st->st_connection->policy
							   & (POLICY_XAUTH_RSASIG | POLICY_XAUTH_PSK))
							   != LEMPTY;
			is_xauth_server =  (st->st_connection->policy
							   & POLICY_XAUTH_SERVER)
							   != LEMPTY;

			/* Should we start XAUTH as a server */
			if (has_xauth_policy && is_xauth_server
			&& IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			&& !st->st_xauth.started)
			{
				DBG(DBG_CONTROL,
					DBG_log("starting XAUTH server")
				)
				xauth_send_request(st);
				break;
			}

			/* Wait for XAUTH request from server */
			if (has_xauth_policy && !is_xauth_server
			&& IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			&& !st->st_xauth.started)
			{
				DBG(DBG_CONTROL,
					DBG_log("waiting for XAUTH request from server")
				)
				break;
			}

			/* Should we start ModeConfig as a client? */
			if (st->st_connection->spd.this.modecfg
			&& IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			&& !(st->st_connection->policy & POLICY_MODECFG_PUSH)
			&& !st->st_modecfg.started)
			{
				DBG(DBG_CONTROL,
					DBG_log("starting ModeCfg client in pull mode")
				)
				modecfg_send_request(st);
				break;
			}

			/* Should we start ModeConfig as a server? */
			if (st->st_connection->spd.that.modecfg
			&& IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			&& !st->st_modecfg.started
			&& (st->st_connection->policy & POLICY_MODECFG_PUSH))
			{
				DBG(DBG_CONTROL,
					DBG_log("starting ModeCfg server in push mode")
				)
				modecfg_send_set(st);
				break;
			}

			/* Wait for ModeConfig set from server */
			if (st->st_connection->spd.this.modecfg
			&& IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			&& !st->st_modecfg.vars_set)
			{
				DBG(DBG_CONTROL,
					DBG_log("waiting for ModeCfg set from server")
				)
				break;
			}

			if (smc->flags & SMF_RELEASE_PENDING_P2)
			{
				/* Initiate any Quick Mode negotiations that
				 * were waiting to piggyback on this Keying Channel.
				 *
				 * ??? there is a potential race condition
				 * if we are the responder: the initial Phase 2
				 * message might outrun the final Phase 1 message.
				 * I think that retransmission will recover.
				 */
				unpend(st);
			}

			if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)
			||  IS_IPSEC_SA_ESTABLISHED(st->st_state))
				release_whack(st);
			break;

		case STF_INTERNAL_ERROR:
			whack_log(RC_INTERNALERR + md->note
				, "%s: internal error"
				, enum_name(&state_names, st->st_state));

			DBG(DBG_CONTROL,
				DBG_log("state transition function for %s had internal error"
					, enum_name(&state_names, from_state)));
			break;

		default:        /* a shortcut to STF_FAIL, setting md->note */
			passert(result > STF_FAIL);
			md->note = result - STF_FAIL;
			result = STF_FAIL;
			/* FALL THROUGH ... */
		case STF_FAIL:
			/* As it is, we act as if this message never happened:
			 * whatever retrying was in place, remains in place.
			 */
			whack_log(RC_NOTIFICATION + md->note
				, "%s: %s"
				, enum_name(&state_names, (st == NULL)? STATE_MAIN_R0:st->st_state)
				, enum_name(&notification_names, md->note));

			SEND_NOTIFICATION(md->note);

			DBG(DBG_CONTROL,
				DBG_log("state transition function for %s failed: %s"
					, enum_name(&state_names, from_state)
					, enum_name(&notification_names, md->note)));
			break;
	}
}
