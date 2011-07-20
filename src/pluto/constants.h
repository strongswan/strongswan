/* manifest constants
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

#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#include <freeswan.h>

#include <kernel/kernel_ipsec.h>

#include <utils.h>
#include <utils/identification.h>
#include <crypto/hashers/hasher.h>

extern const char compile_time_interop_options[];

extern void init_constants(void);

/*
 * NOTE:For debugging purposes, constants.c has tables to map numbers back to names.
 * Any changes here should be reflected there.
 */

/* Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return
 * a NULL on success and a pointer to constant string on failure.
 * The fact that the string is a constant is limiting, but it
 * avoids storage management issues: the recipient is allowed to assume
 * that the string will live "long enough" (usually forever).
 * <freeswan.h> defines err_t for this return type.
 */

#define NULL_FD (-1)    /* NULL file descriptor */
#define dup_any(fd) ((fd) == NULL_FD? NULL_FD : dup(fd))
#define close_any(fd) { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; } }

/* set type with room for at least 64 elements for ALG opts (was 32 in stock FS) */

typedef unsigned long long lset_t;
#define LEMPTY 0ULL
#define LELEM(opt) (1ULL << (opt))
#define LRANGE(lwb, upb) LRANGES(LELEM(lwb), LELEM(upb))
#define LRANGES(first, last) (last - first + last)
#define LHAS(set, elem)  ((LELEM(elem) & (set)) != LEMPTY)
#define LIN(subset, set)  (((subset) & (set)) == (subset))
#define LDISJOINT(a, b)  (((a) & (b)) == LEMPTY)

/* Control and lock pathnames */
#ifndef IPSEC_PIDDIR
# define IPSEC_PIDDIR "/var/run"
#endif
#ifndef DEFAULT_CTLBASE
# define DEFAULT_CTLBASE IPSEC_PIDDIR "/pluto"
#endif

#define CTL_SUFFIX ".ctl"       /* for UNIX domain socket pathname */
#define LOCK_SUFFIX ".pid"      /* for pluto's lock */
#define INFO_SUFFIX ".info"     /* for UNIX domain socket for apps */

/* Routines to check and display values.
 *
 * An enum_names describes an enumeration.
 * enum_name() returns the name of an enum value, or NULL if invalid.
 * enum_show() is like enum_name, except it formats a numeric representation
 *    for any invalid value (in a static area!)
 *
 * bitnames() formats a display of a set of named bits (in a static area)
 */

struct enum_names {
	unsigned long en_first;  /* first value in range */
	unsigned long en_last;   /* last value in range (inclusive) */
	const char *const *en_names;
	const struct enum_names *en_next_range;     /* descriptor of next range */
};

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);
extern const char *enum_show(enum_names *ed, unsigned long val);
extern int enum_search(enum_names *ed, const char *string);

extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);

/* sparse_names is much like enum_names, except values are
 * not known to be contiguous or ordered.
 * The array of names is ended with one with the name sparse_end
 * (this avoids having to reserve a value to signify the end).
 * Often appropriate for enums defined by others.
 */
struct sparse_name {
	unsigned long val;
	const char *const name;
};
typedef const struct sparse_name sparse_names[];

extern const char *sparse_name(sparse_names sd, unsigned long val);
extern const char *sparse_val_show(sparse_names sd, unsigned long val);
extern const char sparse_end[];

#define FULL_INET_ADDRESS_SIZE    6

/* limits on nonce sizes.  See RFC2409 "The internet key exchange (IKE)" 5 */
#define MINIMUM_NONCE_SIZE      8       /* bytes */
#define DEFAULT_NONCE_SIZE      16      /* bytes */
#define MAXIMUM_NONCE_SIZE      256     /* bytes */

#define COOKIE_SIZE 8
#define MAX_ISAKMP_SPI_SIZE 16

#define DES_CBC_BLOCK_SIZE      (64 / BITS_PER_BYTE)

/* Maximum is required for SHA2_512 */
#define MAX_DIGEST_LEN          HASH_SIZE_SHA512

/* RFC 2404 "HMAC-SHA-1-96" section 3 */
#define HMAC_SHA1_KEY_LEN       HASH_SIZE_SHA1

/* RFC 2403 "HMAC-MD5-96" section 3 */
#define HMAC_MD5_KEY_LEN        HASH_SIZE_MD5

#define IKE_UDP_PORT    500

/* IPsec AH transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.3
 * and in http://www.iana.org/assignments/isakmp-registry
 */
enum ipsec_authentication_algo {
	AH_NONE         = 0,
	AH_MD5          = 2,
	AH_SHA          = 3,
	AH_DES          = 4,
	AH_SHA2_256     = 5,
	AH_SHA2_384     = 6,
	AH_SHA2_512     = 7,
	AH_RIPEMD       = 8,
	AH_AES_XCBC_MAC = 9,
	AH_RSA          = 10,
	AH_AES_128_GMAC = 11,
	AH_AES_192_GMAC = 12,
	AH_AES_256_GMAC = 13,
	AH_SHA2_256_96  = 252
};

extern enum_names ah_transform_names;

/* IPsec ESP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.4
 * and from http://www.iana.org/assignments/isakmp-registry
 */

enum ipsec_cipher_algo {
	ESP_NONE          = 0,
	ESP_DES_IV64      = 1,
	ESP_DES           = 2,
	ESP_3DES          = 3,
	ESP_RC5           = 4,
	ESP_IDEA          = 5,
	ESP_CAST          = 6,
	ESP_BLOWFISH      = 7,
	ESP_3IDEA         = 8,
	ESP_DES_IV32      = 9,
	ESP_RC4           = 10,
	ESP_NULL          = 11,
	ESP_AES           = 12,
	ESP_AES_CTR       = 13,
	ESP_AES_CCM_8     = 14,
	ESP_AES_CCM_12    = 15,
	ESP_AES_CCM_16    = 16,
	ESP_UNASSIGNED_17 = 17,
	ESP_AES_GCM_8     = 18,
	ESP_AES_GCM_12    = 19,
	ESP_AES_GCM_16    = 20,
	ESP_SEED_CBC      = 21,
	ESP_CAMELLIA      = 22,
	ESP_AES_GMAC      = 23,
	ESP_SERPENT       = 252,
	ESP_TWOFISH       = 253
};

extern enum_names esp_transform_names;

/* IPCOMP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.5
 * now defined in kernel/kernel_ipsec.h
 */

extern enum_names ipcomp_transformid_names;

/* Certificate type values
 * RFC 2408 ISAKMP, chapter 3.9
 */
enum ipsec_cert_type {
	CERT_NONE=                0,
	CERT_PKCS7_WRAPPED_X509=  1,
	CERT_PGP=                 2,
	CERT_DNS_SIGNED_KEY=      3,
	CERT_X509_SIGNATURE=      4,
	CERT_X509_KEY_EXCHANGE=   5,
	CERT_KERBEROS_TOKENS=     6,
	CERT_CRL=                 7,
	CERT_ARL=                 8,
	CERT_SPKI=                9,
	CERT_X509_ATTRIBUTE=      10,
	CERT_RAW_RSA_KEY=         11
};

/* RFC 2560 OCSP - certificate status */

typedef enum {
	CERT_GOOD =         0,
	CERT_REVOKED =      1,
	CERT_UNKNOWN =      2,
	CERT_UNDEFINED =    3
} cert_status_t;

/* RFC 3706 Dead Peer Detection */

extern enum_name_t *dpd_action_names;

typedef enum {
	DPD_ACTION_NONE =    0,
	DPD_ACTION_CLEAR =   1,
	DPD_ACTION_HOLD  =   2,
	DPD_ACTION_RESTART = 3,
	DPD_ACTION_UNKNOWN = 4
} dpd_action_t;

/* Timer events */

extern enum_name_t *timer_event_names;

enum event_type {
	EVENT_NULL, /* non-event */
	EVENT_REINIT_SECRET,        /* Refresh cookie secret */
	EVENT_SO_DISCARD,           /* discard unfinished state object */
	EVENT_RETRANSMIT,           /* Retransmit packet */
	EVENT_SA_REPLACE,           /* SA replacement event */
	EVENT_SA_REPLACE_IF_USED,   /* SA replacement event */
	EVENT_SA_EXPIRE,            /* SA expiration event */
	EVENT_NAT_T_KEEPALIVE,      /* NAT Traversal Keepalive */
	EVENT_DPD,                  /* dead peer detection */
	EVENT_DPD_TIMEOUT,          /* dead peer detection timeout */
	EVENT_LOG_DAILY             /* reset certain log events/stats */
};

#define EVENT_REINIT_SECRET_DELAY               3600 /* 1 hour */
#define EVENT_RETRANSMIT_DELAY_0                10   /* 10 seconds */

/* Misc. stuff */

#define MAXIMUM_RETRANSMISSIONS              2
#define MAXIMUM_RETRANSMISSIONS_INITIAL      20

#define MAX_INPUT_UDP_SIZE             65536
#define MAX_OUTPUT_UDP_SIZE            65536

/* Version numbers */

#define ISAKMP_MAJOR_VERSION   0x1
#define ISAKMP_MINOR_VERSION   0x0

extern enum_names version_names;

/* Domain of Interpretation */

extern enum_names doi_names;

#define ISAKMP_DOI_ISAKMP          0
#define ISAKMP_DOI_IPSEC           1

/* IPsec DOI things */

#define IPSEC_DOI_SITUATION_LENGTH 4
#define IPSEC_DOI_LDI_LENGTH       4
#define IPSEC_DOI_SPI_SIZE         4

/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
 * ESP: RFC 2402 2.4; AH: RFC 2406 2.1
 * IPComp RFC 2393 substitutes a CPI in the place of an SPI.
 * see also draft-shacham-ippcp-rfc2393bis-05.txt.
 * We (FreeS/WAN) reserve 0x100 to 0xFFF for manual keying, so
 * Pluto won't generate these values.
 */
#define IPSEC_DOI_SPI_MIN          0x100
#define IPSEC_DOI_SPI_OUR_MIN      0x1000

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * IMPAIR_* actually change behaviour, usually badly,
 * to aid in testing.  Naturally, these are not included in ALL.
 *
 * NOTE: changes here must be done in concert with changes to DBGOPT_*
 * in whack.c.  A change to WHACK_MAGIC in whack.h will be required too.
 */
#ifdef DEBUG
extern const char *const debug_bit_names[];
#endif

#define DBG_RAW         LELEM(0)        /* raw packet I/O */
#define DBG_CRYPT       LELEM(1)        /* encryption/decryption of messages */
#define DBG_PARSING     LELEM(2)        /* show decoding of messages */
#define DBG_EMITTING    LELEM(3)        /* show encoding of messages */
#define DBG_CONTROL     LELEM(4)        /* control flow within Pluto */
#define DBG_LIFECYCLE   LELEM(5)        /* SA lifecycle */
#define DBG_KERNEL      LELEM(6)        /* messages to kernel */
#define DBG_DNS         LELEM(7)        /* DNS activity */
#define DBG_NATT        LELEM(8)        /* NAT-T */
#define DBG_OPPO        LELEM(9)        /* opportunism */
#define DBG_CONTROLMORE LELEM(10)       /* more detailed debugging */

#define DBG_PRIVATE     LELEM(11)       /* private information: DANGER! */

#define IMPAIR0 12      /* first bit for IMPAIR_* */

#define IMPAIR_DELAY_ADNS_KEY_ANSWER    LELEM(IMPAIR0+0)        /* sleep before answering */
#define IMPAIR_DELAY_ADNS_TXT_ANSWER    LELEM(IMPAIR0+1)        /* sleep before answering */
#define IMPAIR_BUST_MI2 LELEM(IMPAIR0+2)        /* make MI2 really large */
#define IMPAIR_BUST_MR2 LELEM(IMPAIR0+3)        /* make MI2 really large */

#define DBG_NONE        0       /* no options on, including impairments */
#define DBG_ALL         LRANGES(DBG_RAW, DBG_CONTROLMORE)  /* all logging options on EXCEPT DBG_PRIVATE */

/* State of exchanges
 *
 * The name of the state describes the last message sent, not the
 * message currently being input or output (except during retry).
 * In effect, the state represents the last completed action.
 *
 * Messages are named [MQ][IR]n where
 * - M stands for Main Mode (Phase 1);
 *   Q stands for Quick Mode (Phase 2)
 * - I stands for Initiator;
 *   R stands for Responder
 * - n, a digit, stands for the number of the message
 *
 * It would be more convenient if each state accepted a message
 * and produced one.  This is the case for states at the start
 * or end of an exchange.  To fix this, we pretend that there are
 * MR0 and QR0 messages before the MI1 and QR1 messages.  Similarly,
 * we pretend that there are MR4 and QR2 messages.
 *
 * STATE_MAIN_R0 and STATE_QUICK_R0 are intermediate states (not
 * retained between messages) representing the state that accepts the
 * first message of an exchange has been read but not processed.
 *
 * state_microcode state_microcode_table in demux.c describes
 * other important details.
 */

extern enum_names state_names;
extern const char *const state_story[];

enum state_kind {
	STATE_UNDEFINED,    /* 0 -- most likely accident */

	/* IKE states */

	STATE_MAIN_R0,
	STATE_MAIN_I1,
	STATE_MAIN_R1,
	STATE_MAIN_I2,
	STATE_MAIN_R2,
	STATE_MAIN_I3,
	STATE_MAIN_R3,
	STATE_MAIN_I4,

	STATE_QUICK_R0,
	STATE_QUICK_I1,
	STATE_QUICK_R1,
	STATE_QUICK_I2,
	STATE_QUICK_R2,

	STATE_INFO,
	STATE_INFO_PROTECTED,

	/* XAUTH states */

	STATE_XAUTH_I0,              /* initiator state (client) */
	STATE_XAUTH_R1,              /* responder state (server) */
	STATE_XAUTH_I1,
	STATE_XAUTH_R2,
	STATE_XAUTH_I2,
	STATE_XAUTH_R3,

	/* Mode Config pull states */

	STATE_MODE_CFG_R0,           /* responder state (server) */
	STATE_MODE_CFG_I1,           /* initiator state (client) */
	STATE_MODE_CFG_R1,
	STATE_MODE_CFG_I2,

	/* Mode Config push states */

	STATE_MODE_CFG_I0,           /* initiator state (client) */
	STATE_MODE_CFG_R3,           /* responder state (server) */
	STATE_MODE_CFG_I3,
	STATE_MODE_CFG_R4,

	STATE_IKE_ROOF
};

#define STATE_IKE_FLOOR STATE_MAIN_R0

#define PHASE1_INITIATOR_STATES  (LELEM(STATE_MAIN_I1) | LELEM(STATE_MAIN_I2) \
	| LELEM(STATE_MAIN_I3) | LELEM(STATE_MAIN_I4))
#define ISAKMP_SA_ESTABLISHED_STATES ( \
	  LELEM(STATE_MAIN_R3)     | LELEM(STATE_MAIN_I4)     \
	| LELEM(STATE_XAUTH_R1)    | LELEM(STATE_XAUTH_R2) | LELEM(STATE_XAUTH_R3) \
	| LELEM(STATE_XAUTH_I1)    | LELEM(STATE_XAUTH_I2)    \
	| LELEM(STATE_MODE_CFG_I1) | LELEM(STATE_MODE_CFG_R1) | LELEM(STATE_MODE_CFG_I2) \
	| LELEM(STATE_MODE_CFG_R3) | LELEM(STATE_MODE_CFG_I3) | LELEM(STATE_MODE_CFG_R4))

#define IS_PHASE1(s) ((STATE_MAIN_R0 <= (s) && (s) <= STATE_MAIN_I4) \
				   || (STATE_XAUTH_I0 <= (s) && (s) <= STATE_XAUTH_R3) \
				   || (STATE_MODE_CFG_R0 <= (s) && (s) <= STATE_MODE_CFG_R4))

#define IS_QUICK(s) (STATE_QUICK_R0 <= (s) && (s) <= STATE_QUICK_R2)
#define IS_ISAKMP_ENCRYPTED(s) (STATE_MAIN_I2 <= (s))

#define IS_ISAKMP_SA_ESTABLISHED(s) (        \
				   (s) == STATE_MAIN_R3      \
				|| (s) == STATE_MAIN_I4      \
				|| (s) == STATE_XAUTH_I2     \
				|| (s) == STATE_XAUTH_R3     \
				|| (s) == STATE_MODE_CFG_R1  \
				|| (s) == STATE_MODE_CFG_I2  \
				|| (s) == STATE_MODE_CFG_I3  \
				|| (s) == STATE_MODE_CFG_R4)

#define IS_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_I2 || (s) == STATE_QUICK_R2)
#define IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_R1)

/* kind of struct connection
 * Ordered (mostly) by concreteness.  Order is exploited.
 */

extern enum_names connection_kind_names;

enum connection_kind {
	CK_GROUP,           /* policy group: instantiates to template */
	CK_TEMPLATE,        /* abstract connection, with wildcard */
	CK_PERMANENT,       /* normal connection */
	CK_INSTANCE,        /* instance of template, created for a particular attempt */
	CK_GOING_AWAY       /* instance being deleted -- don't delete again */
};


/* routing status.
 * Note: routing ignores source address, but erouting does not!
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */

extern enum_names routing_story;

/* note that this is assumed to be ordered! */
enum routing_t {
	RT_UNROUTED,        /* unrouted */
	RT_UNROUTED_HOLD,   /* unrouted, but HOLD shunt installed */
	RT_ROUTED_ECLIPSED, /* RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
	RT_ROUTED_PROSPECTIVE,      /* routed, and prospective shunt installed */
	RT_ROUTED_HOLD,     /* routed, and HOLD shunt installed */
	RT_ROUTED_FAILURE,  /* routed, and failure-context shunt installed */
	RT_ROUTED_TUNNEL,   /* routed, and erouted to an IPSEC SA group */
	RT_UNROUTED_KEYED   /* keyed, but not routed, on purpose */
};

#define routed(rs) ((rs) > RT_UNROUTED_HOLD)
#define erouted(rs) ((rs) != RT_UNROUTED)
#define shunt_erouted(rs) (erouted(rs) && (rs) != RT_ROUTED_TUNNEL)

/* Payload types
 * RFC2408 Internet Security Association and Key Management Protocol (ISAKMP)
 * section 3.1
 *
 * RESERVED 14-127
 * Private USE 128-255
 */

extern enum_names payload_names;
extern const char *const payload_name[];

#define ISAKMP_NEXT_NONE       0        /* No other payload following */
#define ISAKMP_NEXT_SA         1        /* Security Association */
#define ISAKMP_NEXT_P          2        /* Proposal */
#define ISAKMP_NEXT_T          3        /* Transform */
#define ISAKMP_NEXT_KE         4        /* Key Exchange */
#define ISAKMP_NEXT_ID         5        /* Identification */
#define ISAKMP_NEXT_CERT       6        /* Certificate */
#define ISAKMP_NEXT_CR         7        /* Certificate Request */
#define ISAKMP_NEXT_HASH       8        /* Hash */
#define ISAKMP_NEXT_SIG        9        /* Signature */
#define ISAKMP_NEXT_NONCE      10       /* Nonce */
#define ISAKMP_NEXT_N          11       /* Notification */
#define ISAKMP_NEXT_D          12       /* Delete */
#define ISAKMP_NEXT_VID        13       /* Vendor ID */
#define ISAKMP_NEXT_ATTR       14       /* Mode config Attribute */

#define ISAKMP_NEXT_NATD_RFC   20       /* NAT-Traversal: NAT-D (rfc) */
#define ISAKMP_NEXT_NATOA_RFC  21       /* NAT-Traversal: NAT-OA (rfc) */
#define ISAKMP_NEXT_ROOF       22       /* roof on payload types */

#define ISAKMP_NEXT_NATD_DRAFTS   130   /* NAT-Traversal: NAT-D (drafts) */
#define ISAKMP_NEXT_NATOA_DRAFTS  131   /* NAT-Traversal: NAT-OA (drafts) */

/* These values are to be used within the Type field of an Attribute (14)
 * ISAKMP payload.
 */
#define ISAKMP_CFG_REQUEST         1
#define ISAKMP_CFG_REPLY           2
#define ISAKMP_CFG_SET             3
#define ISAKMP_CFG_ACK             4

extern enum_names attr_msg_type_names;

extern enum_names modecfg_attr_names;

/* XAUTH authentication types */
#define XAUTH_TYPE_GENERIC 0
#define XAUTH_TYPE_CHAP    1
#define XAUTH_TYPE_OTP     2
#define XAUTH_TYPE_SKEY    3

/* Values for XAUTH_STATUS */
#define XAUTH_STATUS_FAIL       0
#define XAUTH_STATUS_OK         1

extern enum_names xauth_type_names;

/* Exchange types
 * RFC2408 "Internet Security Association and Key Management Protocol (ISAKMP)"
 * section 3.1
 *
 * ISAKMP Future Use     6 - 31
 * DOI Specific Use     32 - 239
 * Private Use         240 - 255
 *
 * Note: draft-ietf-ipsec-dhless-enc-mode-00.txt Appendix A
 * defines "DHless RSA Encryption" as 6.
 */

extern enum_names exchange_names;

#define ISAKMP_XCHG_NONE       0
#define ISAKMP_XCHG_BASE       1
#define ISAKMP_XCHG_IDPROT     2        /* ID Protection */
#define ISAKMP_XCHG_AO         3        /* Authentication Only */
#define ISAKMP_XCHG_AGGR       4        /* Aggressive */
#define ISAKMP_XCHG_INFO       5        /* Informational */
#define ISAKMP_XCHG_MODE_CFG   6        /* Mode Config */

/* Extra exchange types, defined by Oakley
 * RFC2409 "The Internet Key Exchange (IKE)", near end of Appendix A
 */
#define ISAKMP_XCHG_QUICK      32       /* Oakley Quick Mode */
#define ISAKMP_XCHG_NGRP       33       /* Oakley New Group Mode */
/* added in draft-ietf-ipsec-ike-01.txt, near end of Appendix A */
#define ISAKMP_XCHG_ACK_INFO   34       /* Oakley Acknowledged Informational */

/* Flag bits */

extern const char *const flag_bit_names[];

#define ISAKMP_FLAG_ENCRYPTION   0x1
#define ISAKMP_FLAG_COMMIT       0x2

/* Situation definition for IPsec DOI */

extern const char *const sit_bit_names[];

#define SIT_IDENTITY_ONLY        0x01
#define SIT_SECRECY              0x02
#define SIT_INTEGRITY            0x04

/* Protocol IDs
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.1
 */

extern enum_names protocol_names;

#define PROTO_ISAKMP             1
#define PROTO_IPSEC_AH           2
#define PROTO_IPSEC_ESP          3
#define PROTO_IPCOMP             4

/* warning: trans_show uses enum_show, so same static buffer is used */
#define trans_show(p, t) \
	((p)==PROTO_IPSEC_AH ? enum_show(&ah_transformid_names, (t)) \
	: (p)==PROTO_IPSEC_ESP ? enum_show(&esp_transformid_names, (t)) \
	: (p)==PROTO_IPCOMP ? enum_show(&ipcomp_transformid_names, (t)) \
	: "??")

#define KEY_IKE               1

extern enum_names isakmp_transformid_names;

/* the following are from RFC 2393/draft-shacham-ippcp-rfc2393bis-05.txt 3.3 */
typedef u_int16_t cpi_t;
#define IPCOMP_CPI_SIZE          2
#define IPCOMP_FIRST_NEGOTIATED  256
#define IPCOMP_LAST_NEGOTIATED   61439

/* Identification type values
 * RFC 2407 The Internet IP security Domain of Interpretation for ISAKMP 4.6.2.1
 */

extern enum_names ident_names;
extern enum_names cert_type_names;

extern enum_name_t *cert_policy_names;

typedef enum certpolicy {
	CERT_ALWAYS_SEND   = 0,
	CERT_SEND_IF_ASKED = 1,
	CERT_NEVER_SEND    = 2,

	CERT_YES_SEND      = 3,       /* synonym for CERT_ALWAYS_SEND */
	CERT_NO_SEND       = 4        /* synonym for CERT_NEVER_SEND  */
} certpolicy_t;

/* Policies for establishing an SA
 *
 * These are used to specify attributes (eg. encryption) and techniques
 * (eg PFS) for an SA.
 * Note: certain CD_ definitions in whack.c parallel these -- keep them
 * in sync!
 */

extern const char *const sa_policy_bit_names[];
extern const char *prettypolicy(lset_t policy);

/* ISAKMP auth techniques (none means never negotiate) */
#define POLICY_PSK           LELEM(0)
#define POLICY_PUBKEY        LELEM(1)

#define POLICY_ISAKMP_SHIFT     0       /* log2(POLICY_PSK) */
#define POLICY_ID_AUTH_MASK     (POLICY_PSK | POLICY_PUBKEY | POLICY_XAUTH_PSK | POLICY_XAUTH_RSASIG)
#define POLICY_ISAKMP_MASK      POLICY_ID_AUTH_MASK     /* all so far */

/* Quick Mode (IPSEC) attributes */
#define POLICY_ENCRYPT       LELEM(2)   /* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE  LELEM(3)   /* must be second */
#define POLICY_COMPRESS      LELEM(4)   /* must be third */
#define POLICY_TUNNEL        LELEM(5)
#define POLICY_PFS           LELEM(6)
#define POLICY_DISABLEARRIVALCHECK  LELEM(7)    /* suppress tunnel egress address checking */

#define POLICY_IPSEC_SHIFT      2       /* log2(POLICY_ENCRYPT) */
#define POLICY_IPSEC_MASK       LRANGES(POLICY_ENCRYPT, POLICY_DISABLEARRIVALCHECK)

/* shunt attributes: what to do when routed without tunnel (2 bits) */
#define POLICY_SHUNT_SHIFT      8       /* log2(POLICY_SHUNT_PASS) */
#define POLICY_SHUNT_MASK       (03ul << POLICY_SHUNT_SHIFT)

#define POLICY_SHUNT_TRAP       (0ul << POLICY_SHUNT_SHIFT) /* default: negotiate */
#define POLICY_SHUNT_PASS       (1ul << POLICY_SHUNT_SHIFT)
#define POLICY_SHUNT_DROP       (2ul << POLICY_SHUNT_SHIFT)
#define POLICY_SHUNT_REJECT     (3ul << POLICY_SHUNT_SHIFT)

/* fail attributes: what to do with failed negotiation (2 bits) */

#define POLICY_FAIL_SHIFT       10      /* log2(POLICY_FAIL_PASS) */
#define POLICY_FAIL_MASK        (03ul << POLICY_FAIL_SHIFT)

#define POLICY_FAIL_NONE     (0ul << POLICY_FAIL_SHIFT) /* default */
#define POLICY_FAIL_PASS     (1ul << POLICY_FAIL_SHIFT)
#define POLICY_FAIL_DROP     (2ul << POLICY_FAIL_SHIFT)
#define POLICY_FAIL_REJECT   (3ul << POLICY_FAIL_SHIFT)

/* connection policy
 * Other policies could vary per state object.  These live in connection.
 */
#define POLICY_DONT_REKEY       LELEM(12)       /* don't rekey state either Phase */
#define POLICY_OPPO             LELEM(13)       /* is this opportunistic? */
#define POLICY_GROUP            LELEM(14)       /* is this a group template? */
#define POLICY_GROUTED          LELEM(15)       /* do we want this group routed? */
#define POLICY_UP               LELEM(16)       /* do we want this up? */
#define POLICY_MODECFG_PUSH     LELEM(17)       /* is modecfg pushed by server? */
#define POLICY_XAUTH_PSK        LELEM(18)       /* do we support XAUTH????PreShared? */
#define POLICY_XAUTH_RSASIG     LELEM(19)       /* do we support XAUTH????RSA? */
#define POLICY_XAUTH_SERVER     LELEM(20)       /* are we an XAUTH server? */
#define POLICY_DONT_REAUTH      LELEM(21)       /* don't reauthenticate on rekeying, IKEv2 only */
#define POLICY_BEET             LELEM(22)       /* bound end2end tunnel, IKEv2 */
#define POLICY_MOBIKE           LELEM(23)       /* enable MOBIKE for IKEv2  */
#define POLICY_FORCE_ENCAP      LELEM(24)       /* force UDP encapsulation (IKEv2)  */
#define POLICY_PROXY            LELEM(25)       /* proxy transport mode (MIPv6) */

/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

/* Don't allow negotiation? */
#define NEVER_NEGOTIATE(p)  (LDISJOINT((p), POLICY_ID_AUTH_MASK))


/* Oakley transform attributes
 * draft-ietf-ipsec-ike-01.txt appendix A
 */

extern enum_names oakley_attr_names;
extern const char *const oakley_attr_bit_names[];

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6        /* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7        /* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8        /* B/V */
#define OAKLEY_GROUP_CURVE_A           9        /* B/V */
#define OAKLEY_GROUP_CURVE_B          10        /* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12        /* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16        /* B/V */
#define OAKLEY_BLOCK_SIZE             17

/* for each Oakley attribute, which enum_names describes its values? */
extern enum_names *oakley_attr_val_descs[];

/* IPsec DOI attributes
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 */

extern enum_names ipsec_attr_names;

#define SA_LIFE_TYPE             1
#define SA_LIFE_DURATION         2      /* B/V */
#define GROUP_DESCRIPTION        3
#define ENCAPSULATION_MODE       4
#define AUTH_ALGORITHM           5
#define KEY_LENGTH               6
#define KEY_ROUNDS               7
#define COMPRESS_DICT_SIZE       8
#define COMPRESS_PRIVATE_ALG     9      /* B/V */

/* for each IPsec attribute, which enum_names describes its values? */
extern enum_names *ipsec_attr_val_descs[];

/* SA Lifetime Type attribute
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 * Default time specified in 4.5
 *
 * There are two defaults for IPSEC SA lifetime, SA_LIFE_DURATION_DEFAULT,
 * and PLUTO_SA_LIFE_DURATION_DEFAULT.
 * SA_LIFE_DURATION_DEFAULT is specified in RFC2407 "The Internet IP
 * Security Domain of Interpretation for ISAKMP" 4.5.  It applies when
 * an ISAKMP negotiation does not explicitly specify a life duration.
 * PLUTO_SA_LIFE_DURATION_DEFAULT is specified in pluto(8).  It applies
 * when a connection description does not specify --ipseclifetime.
 * The value of SA_LIFE_DURATION_MAXIMUM is our local policy.
 */

extern enum_names sa_lifetime_names;

#define SA_LIFE_TYPE_SECONDS   1
#define SA_LIFE_TYPE_KBYTES    2

#define SA_LIFE_DURATION_DEFAULT          28800 /* eight hours (RFC2407 4.5) */
#define PLUTO_SA_LIFE_DURATION_DEFAULT     3600 /* one hour    (pluto(8)) */
#define SA_LIFE_DURATION_MAXIMUM          86400 /* one day */

#define SA_REPLACEMENT_MARGIN_DEFAULT       540 /* (IPSEC & IKE) nine minutes */
#define SA_REPLACEMENT_FUZZ_DEFAULT         100 /* (IPSEC & IKE) 100% of MARGIN */
#define SA_REPLACEMENT_RETRIES_DEFAULT        3 /* (IPSEC & IKE) */

#define SA_LIFE_DURATION_K_DEFAULT  0xFFFFFFFFlu

/* Encapsulation Mode attribute */

extern enum_names enc_mode_names;

#define ENCAPSULATION_MODE_UNSPECIFIED 0        /* not legal -- used internally */
#define ENCAPSULATION_MODE_TUNNEL      1
#define ENCAPSULATION_MODE_TRANSPORT   2

#define ENCAPSULATION_MODE_UDP_TUNNEL_RFC          3
#define ENCAPSULATION_MODE_UDP_TRANSPORT_RFC       4

#define ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS       61443
#define ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS    61444

/* Auth Algorithm attribute */

extern enum_names auth_alg_names, extended_auth_alg_names;

#define AUTH_ALGORITHM_NONE                0  /* our private designation */
#define AUTH_ALGORITHM_HMAC_MD5            1
#define AUTH_ALGORITHM_HMAC_SHA1           2
#define AUTH_ALGORITHM_DES_MAC             3
#define AUTH_ALGORITHM_KPDK                4
#define AUTH_ALGORITHM_HMAC_SHA2_256       5
#define AUTH_ALGORITHM_HMAC_SHA2_384       6
#define AUTH_ALGORITHM_HMAC_SHA2_512       7
#define AUTH_ALGORITHM_HMAC_RIPEMD         8
#define AUTH_ALGORITHM_AES_XCBC_MAC        9
#define AUTH_ALGORITHM_SIG_RSA            10
#define AUTH_ALGORITHM_AES_128_GMAC       11
#define AUTH_ALGORITHM_AES_192_GMAC       12
#define AUTH_ALGORITHM_AES_256_GMAC       13
#define AUTH_ALGORITHM_NULL              251
#define AUTH_ALGORITHM_HMAC_SHA2_256_96  252

/* Oakley Lifetime Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * As far as I can see, there is not specification for
 * OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT.  This could lead to interop problems!
 * For no particular reason, we chose three hours.
 * The value of OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM is our local policy.
 */
extern enum_names oakley_lifetime_names;

#define OAKLEY_LIFE_SECONDS   1
#define OAKLEY_LIFE_KILOBYTES 2

#define OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT 10800   /* three hours */
#define OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM 86400   /* one day */

/* Oakley PRF attribute (none defined)
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_prf_names;

/* HMAC (see rfc2104.txt) */

#define HMAC_IPAD            0x36
#define HMAC_OPAD            0x5C

/* Oakley Encryption Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_enc_names;

#define OAKLEY_DES_CBC                  1
#define OAKLEY_IDEA_CBC                 2
#define OAKLEY_BLOWFISH_CBC             3
#define OAKLEY_RC5_R16_B64_CBC          4
#define OAKLEY_3DES_CBC                 5
#define OAKLEY_CAST_CBC                 6
#define OAKLEY_AES_CBC                  7
#define OAKLEY_CAMELLIA_CBC             8

#define OAKLEY_MARS_CBC                 65001
#define OAKLEY_RC6_CBC                  65002
#define OAKLEY_ID_65003                 65003
#define OAKLEY_SERPENT_CBC              65004
#define OAKLEY_TWOFISH_CBC              65005

#define OAKLEY_TWOFISH_CBC_SSH          65289

#define OAKLEY_ENCRYPT_MAX              65535   /* pretty useless :) */

/* Oakley Hash Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_hash_names;

#define OAKLEY_MD5              1
#define OAKLEY_SHA              2
#define OAKLEY_TIGER            3
#define OAKLEY_SHA2_256         4
#define OAKLEY_SHA2_384         5
#define OAKLEY_SHA2_512         6

#define OAKLEY_HASH_MAX         7

/* Oakley Authentication Method attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * Goofy Hybrid extensions from draft-ietf-ipsec-isakmp-hybrid-auth-05.txt
 * Goofy XAUTH extensions from draft-ietf-ipsec-isakmp-xauth-06.txt
 */

extern enum_names oakley_auth_names;

#define OAKLEY_PRESHARED_KEY       1
#define OAKLEY_DSS_SIG             2
#define OAKLEY_RSA_SIG             3
#define OAKLEY_RSA_ENC             4
#define OAKLEY_RSA_ENC_REV         5
#define OAKLEY_ELGAMAL_ENC         6
#define OAKLEY_ELGAMAL_ENC_REV     7
#define OAKLEY_ECDSA_SIG           8
#define OAKLEY_ECDSA_256           9
#define OAKLEY_ECDSA_384          10
#define OAKLEY_ECDSA_521          11

#define OAKLEY_AUTH_ROOF          12    /* roof on auth values THAT WE SUPPORT */

#define HybridInitRSA                   64221
#define HybridRespRSA                   64222
#define HybridInitDSS                   64223
#define HybridRespDSS                   64224

#define XAUTHInitPreShared              65001
#define XAUTHRespPreShared              65002
#define XAUTHInitDSS                    65003
#define XAUTHRespDSS                    65004
#define XAUTHInitRSA                    65005
#define XAUTHRespRSA                    65006
#define XAUTHInitRSAEncryption          65007
#define XAUTHRespRSAEncryption          65008
#define XAUTHInitRSARevisedEncryption   65009
#define XAUTHRespRSARevisedEncryption   65010

/* Oakley Group Description attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_names;

/*      you must also touch: constants.c, crypto.c */

/* Oakley Group Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_type_names;

#define OAKLEY_GROUP_TYPE_MODP     1
#define OAKLEY_GROUP_TYPE_ECP      2
#define OAKLEY_GROUP_TYPE_EC2N     3


/* Notify messages -- error types
 * See RFC2408 ISAKMP 3.14.1
 */

extern enum_names notification_names;
extern enum_names ipsec_notification_names;

typedef enum {
	ISAKMP_NOTHING_WRONG =              0,  /* unofficial! */

	ISAKMP_INVALID_PAYLOAD_TYPE =       1,
	ISAKMP_DOI_NOT_SUPPORTED =          2,
	ISAKMP_SITUATION_NOT_SUPPORTED =    3,
	ISAKMP_INVALID_COOKIE =             4,
	ISAKMP_INVALID_MAJOR_VERSION =      5,
	ISAKMP_INVALID_MINOR_VERSION =      6,
	ISAKMP_INVALID_EXCHANGE_TYPE =      7,
	ISAKMP_INVALID_FLAGS =              8,
	ISAKMP_INVALID_MESSAGE_ID =         9,
	ISAKMP_INVALID_PROTOCOL_ID =       10,
	ISAKMP_INVALID_SPI =               11,
	ISAKMP_INVALID_TRANSFORM_ID =      12,
	ISAKMP_ATTRIBUTES_NOT_SUPPORTED =  13,
	ISAKMP_NO_PROPOSAL_CHOSEN =        14,
	ISAKMP_BAD_PROPOSAL_SYNTAX =       15,
	ISAKMP_PAYLOAD_MALFORMED =         16,
	ISAKMP_INVALID_KEY_INFORMATION =   17,
	ISAKMP_INVALID_ID_INFORMATION =    18,
	ISAKMP_INVALID_CERT_ENCODING =     19,
	ISAKMP_INVALID_CERTIFICATE =       20,
	ISAKMP_CERT_TYPE_UNSUPPORTED =     21,
	ISAKMP_INVALID_CERT_AUTHORITY =    22,
	ISAKMP_INVALID_HASH_INFORMATION =  23,
	ISAKMP_AUTHENTICATION_FAILED =     24,
	ISAKMP_INVALID_SIGNATURE =         25,
	ISAKMP_ADDRESS_NOTIFICATION =      26,
	ISAKMP_NOTIFY_SA_LIFETIME =        27,
	ISAKMP_CERTIFICATE_UNAVAILABLE =   28,
	ISAKMP_UNSUPPORTED_EXCHANGE_TYPE = 29,
	ISAKMP_UNEQUAL_PAYLOAD_LENGTHS =   30,

	/* ISAKMP status type */
	ISAKMP_CONNECTED =              16384,

	/* IPSEC DOI additions; status types (RFC2407 IPSEC DOI 4.6.3)
	 * These must be sent under the protection of an ISAKMP SA.
	 */
	IPSEC_RESPONDER_LIFETIME =      24576,
	IPSEC_REPLAY_STATUS =           24577,
	IPSEC_INITIAL_CONTACT =         24578,

	/* RFC 3706 DPD */
	R_U_THERE =                     36136,
	R_U_THERE_ACK =                 36137,

	/* Juniper SRX private use */
	NS_NHTB_INFORM =                40001

	} notification_t;


/* Public key algorithm number
 * Same numbering as used in DNSsec
 * See RFC 2535 DNSsec 3.2 The KEY Algorithm Number Specification.
 * Also found in BIND 8.2.2 include/isc/dst.h as DST algorithm codes.
 */

enum pubkey_alg
{
	PUBKEY_ALG_RSA = 1,
	PUBKEY_ALG_DSA = 3,
};

/* Limits on size of RSA moduli.
 * The upper bound matches that of DNSsec (see RFC 2537).
 * The lower bound must be more than 11 octets for certain
 * the encoding to work, but it must be much larger for any
 * real security.  For now, we require 512 bits.
 */

#define RSA_MIN_OCTETS_RFC      12

#define RSA_MIN_OCTETS  (512 / BITS_PER_BYTE)
#define RSA_MIN_OCTETS_UGH      "RSA modulus too small for security: less than 512 bits"

#define RSA_MAX_OCTETS  (8192 / BITS_PER_BYTE)
#define RSA_MAX_OCTETS_UGH      "RSA modulus too large: more than 8192 bits"

/* Note: RFC 2537 encoding adds a few bytes.  If you use a small
 * modulus like 3, the overhead is only 2 bytes
 */
#define RSA_MAX_ENCODING_BYTES  (RSA_MAX_OCTETS + 2)

/* socket address family info */

struct af_info
{
	int af;
	const char *name;
	size_t ia_sz;
	size_t sa_sz;
	int mask_cnt;
	u_int8_t id_addr, id_subnet, id_range;
	const ip_address *any;
	const ip_subnet *none;      /* 0.0.0.0/32 or IPv6 equivalent */
	const ip_subnet *all;       /* 0.0.0.0/0 or IPv6 equivalent */
};

extern const struct af_info
	af_inet4_info,
	af_inet6_info;

extern const struct af_info *aftoinfo(int af);

extern enum_names af_names;

#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))
extern bool subnetisnone(const ip_subnet *sn);

/* BIND enumerated types */

extern enum_names
	rr_qtype_names,
	rr_type_names,
	rr_class_names;

/* How authenticated is info that might have come from DNS?
 * In order of increasing confidence.
 */
enum dns_auth_level {
	DAL_UNSIGNED,       /* AD in response, but no signature: no authentication */
	DAL_NOTSEC, /* no AD in response: authentication impossible */
	DAL_SIGNED, /* AD and signature in response: authentic */
	DAL_LOCAL   /* locally provided (pretty good) */
};

/*
 * define a macro for use in error messages
 */

#ifdef USE_KEYRR
#define RRNAME "TXT or KEY"
#else
#define RRNAME "TXT"
#endif

/* natt traversal types */
extern const char *const natt_type_bitnames[];

/* secret value for responder cookies */
extern u_char secret_of_the_day[HASH_SIZE_SHA1];

#endif /* _CONSTANTS_H */
