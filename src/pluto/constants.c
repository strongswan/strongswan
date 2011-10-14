/* tables of names for values defined in constants.h
 * Copyright (C) 1998-2002 D. Hugh Redelmeier.
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>

#include <freeswan.h>

#include <attributes/attributes.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "packet.h"

/* string naming compile-time options that have interop implications */

const char compile_time_interop_options[] = ""
#ifdef THREADS
		" THREADS"
#endif
#ifdef SMARTCARD
		" SMARTCARD"
#endif
#ifdef VENDORID
		" VENDORID"
#endif
#ifdef CISCO_QUIRKS
		" CISCO_QUIRKS"
#endif
#ifdef USE_KEYRR
		" KEYRR"
#endif
	;

/* version */

static const char *const version_name[] = {
		"ISAKMP Version 1.0",
};

enum_names version_names =
	{ ISAKMP_MAJOR_VERSION<<ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
		ISAKMP_MAJOR_VERSION<<ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION,
		version_name, NULL };

/* RFC 3706 Dead Peer Detection */

ENUM(dpd_action_names, DPD_ACTION_NONE, DPD_ACTION_RESTART,
	"none",
	"clear",
	"hold",
	"restart"
);

/* Timer events */

ENUM(timer_event_names, EVENT_NULL, EVENT_LOG_DAILY,
	"EVENT_NULL",
	"EVENT_REINIT_SECRET",
	"EVENT_SO_DISCARD",
	"EVENT_RETRANSMIT",
	"EVENT_SA_REPLACE",
	"EVENT_SA_REPLACE_IF_USED",
	"EVENT_SA_EXPIRE",
	"EVENT_NAT_T_KEEPALIVE",
	"EVENT_DPD",
	"EVENT_DPD_TIMEOUT",
	"EVENT_LOG_DAILY"
);

/* Domain of Interpretation */

static const char *const doi_name[] = {
		"ISAKMP_DOI_ISAKMP",
		"ISAKMP_DOI_IPSEC",
};

enum_names doi_names = { ISAKMP_DOI_ISAKMP, ISAKMP_DOI_IPSEC, doi_name, NULL };

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * It turns out that "debug-" is clutter in all contexts this is used,
 * so we leave it off.
 */
#ifdef DEBUG
const char *const debug_bit_names[] = {
	"raw",
	"crypt",
	"parsing",
	"emitting",
	"control",
	"lifecycle",
	"kernel",
	"dns",
	"natt",
	"oppo",
	"controlmore",

	"private",

	"impair-delay-adns-key-answer",
	"impair-delay-adns-txt-answer",
	"impair-bust-mi2",
	"impair-bust-mr2",

	NULL
};
#endif

/* State of exchanges */

static const char *const state_name[] = {
	"STATE_UNDEFINED",

	"STATE_MAIN_R0",
	"STATE_MAIN_I1",
	"STATE_MAIN_R1",
	"STATE_MAIN_I2",
	"STATE_MAIN_R2",
	"STATE_MAIN_I3",
	"STATE_MAIN_R3",
	"STATE_MAIN_I4",

	"STATE_QUICK_R0",
	"STATE_QUICK_I1",
	"STATE_QUICK_R1",
	"STATE_QUICK_I2",
	"STATE_QUICK_R2",

	"STATE_INFO",
	"STATE_INFO_PROTECTED",

	"STATE_XAUTH_I0",
	"STATE_XAUTH_R1",
	"STATE_XAUTH_I1",
	"STATE_XAUTH_R2",
	"STATE_XAUTH_I2",
	"STATE_XAUTH_R3",

	"STATE_MODE_CFG_R0",
	"STATE_MODE_CFG_I1",
	"STATE_MODE_CFG_R1",
	"STATE_MODE_CFG_I2",

	"STATE_MODE_CFG_I0",
	"STATE_MODE_CFG_R3",
	"STATE_MODE_CFG_I3",
	"STATE_MODE_CFG_R4",

	"STATE_IKE_ROOF"
};

enum_names state_names =
	{ STATE_UNDEFINED, STATE_IKE_ROOF-1, state_name, NULL };

/* story for state */

const char *const state_story[] = {
	"undefined state after error",			 /* STATE_UNDEFINED */
	"expecting MI1",                         /* STATE_MAIN_R0 */
	"sent MI1, expecting MR1",               /* STATE_MAIN_I1 */
	"sent MR1, expecting MI2",               /* STATE_MAIN_R1 */
	"sent MI2, expecting MR2",               /* STATE_MAIN_I2 */
	"sent MR2, expecting MI3",               /* STATE_MAIN_R2 */
	"sent MI3, expecting MR3",               /* STATE_MAIN_I3 */
	"sent MR3, ISAKMP SA established",       /* STATE_MAIN_R3 */
	"ISAKMP SA established",                 /* STATE_MAIN_I4 */

	"expecting QI1",                         /* STATE_QUICK_R0 */
	"sent QI1, expecting QR1",               /* STATE_QUICK_I1 */
	"sent QR1, inbound IPsec SA installed, expecting QI2",  /* STATE_QUICK_R1 */
	"sent QI2, IPsec SA established",        /* STATE_QUICK_I2 */
	"IPsec SA established",                  /* STATE_QUICK_R2 */

	"got Informational Message in clear",    /* STATE_INFO */
	"got encrypted Informational Message",   /* STATE_INFO_PROTECTED */

	"expecting XAUTH request",               /* STATE_XAUTH_I0 */
	"sent XAUTH request, expecting reply",   /* STATE_XAUTH_R1 */
	"sent XAUTH reply, expecting status",    /* STATE_XAUTH_I1 */
	"sent XAUTH status, expecting ack",      /* STATE_XAUTH_R2 */
	"sent XAUTH ack, established",           /* STATE_XAUTH_I2 */
	"received XAUTH ack, established",       /* STATE_XAUTH_R3 */

	"expecting ModeCfg request",             /* STATE_MODE_CFG_R0 */
	"sent ModeCfg request, expecting reply", /* STATE_MODE_CFG_I1 */
	"sent ModeCfg reply, established",       /* STATE_MODE_CFG_R1 */
	"received ModeCfg reply, established",   /* STATE_MODE_CFG_I2 */

	"expecting ModeCfg set",                 /* STATE_MODE_CFG_I0 */
	"sent ModeCfg set, expecting ack",       /* STATE_MODE_CFG_R3 */
	"sent ModeCfg ack, established",         /* STATE_MODE_CFG_I3 */
	"received ModeCfg ack, established",     /* STATE_MODE_CFG_R4 */
};

/* kind of struct connection */

static const char *const connection_kind_name[] = {
	"CK_GROUP",         /* policy group: instantiates to template */
	"CK_TEMPLATE",      /* abstract connection, with wildcard */
	"CK_PERMANENT",     /* normal connection */
	"CK_INSTANCE",      /* instance of template, created for a particular attempt */
	"CK_GOING_AWAY"     /* instance being deleted -- don't delete again */
};

enum_names connection_kind_names =
	{ CK_GROUP, CK_GOING_AWAY, connection_kind_name, NULL };

/* routing status names */

static const char *const routing_story_strings[] = {
	"unrouted", /* RT_UNROUTED: unrouted */
	"unrouted HOLD",    /* RT_UNROUTED_HOLD: unrouted, but HOLD shunt installed */
	"eroute eclipsed",  /* RT_ROUTED_ECLIPSED: RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
	"prospective erouted",      /* RT_ROUTED_PROSPECTIVE: routed, and prospective shunt installed */
	"erouted HOLD",     /* RT_ROUTED_HOLD: routed, and HOLD shunt installed */
	"fail erouted",     /* RT_ROUTED_FAILURE: routed, and failure-context shunt eroute installed */
	"erouted",  /* RT_ROUTED_TUNNEL: routed, and erouted to an IPSEC SA group */
	"keyed, unrouted",  /* RT_UNROUTED_KEYED: was routed+keyed, but it got turned into an outer policy */
};

enum_names routing_story =
	{ RT_UNROUTED, RT_ROUTED_TUNNEL, routing_story_strings, NULL};

/* Payload types (RFC 2408 "ISAKMP" section 3.1) */

const char *const payload_name[] = {
	"ISAKMP_NEXT_NONE",
	"ISAKMP_NEXT_SA",
	"ISAKMP_NEXT_P",
	"ISAKMP_NEXT_T",
	"ISAKMP_NEXT_KE",
	"ISAKMP_NEXT_ID",
	"ISAKMP_NEXT_CERT",
	"ISAKMP_NEXT_CR",
	"ISAKMP_NEXT_HASH",
	"ISAKMP_NEXT_SIG",
	"ISAKMP_NEXT_NONCE",
	"ISAKMP_NEXT_N",
	"ISAKMP_NEXT_D",
	"ISAKMP_NEXT_VID",
	"ISAKMP_NEXT_MODECFG",
	"ISAKMP_NEXT_15",
	"ISAKMP_NEXT_16",
	"ISAKMP_NEXT_17",
	"ISAKMP_NEXT_18",
	"ISAKMP_NEXT_19",
	"ISAKMP_NEXT_NAT-D",
	"ISAKMP_NEXT_NAT-OA",
	NULL
};

const char *const payload_name_nat_d[] = {
	"ISAKMP_NEXT_NAT-D",
	"ISAKMP_NEXT_NAT-OA", NULL
};

static enum_names payload_names_nat_d =
	{ ISAKMP_NEXT_NATD_DRAFTS, ISAKMP_NEXT_NATOA_DRAFTS, payload_name_nat_d, NULL };

enum_names payload_names =
	{ ISAKMP_NEXT_NONE, ISAKMP_NEXT_NATOA_RFC, payload_name, &payload_names_nat_d };

/* Exchange types (note: two discontinuous ranges) */

static const char *const exchange_name[] = {
	"ISAKMP_XCHG_NONE",
	"ISAKMP_XCHG_BASE",
	"ISAKMP_XCHG_IDPROT",
	"ISAKMP_XCHG_AO",
	"ISAKMP_XCHG_AGGR",
	"ISAKMP_XCHG_INFO",
	"ISAKMP_XCHG_MODE_CFG",
};

static const char *const exchange_name2[] = {
	"ISAKMP_XCHG_QUICK",
	"ISAKMP_XCHG_NGRP",
	"ISAKMP_XCHG_ACK_INFO",
};

static enum_names exchange_desc2 =
	{ ISAKMP_XCHG_QUICK, ISAKMP_XCHG_ACK_INFO, exchange_name2, NULL };

enum_names exchange_names =
	{ ISAKMP_XCHG_NONE, ISAKMP_XCHG_MODE_CFG, exchange_name, &exchange_desc2 };

/* Flag BITS */
const char *const flag_bit_names[] = {
	"ISAKMP_FLAG_ENCRYPTION",
	"ISAKMP_FLAG_COMMIT",
	NULL
};

/* Situation BITS definition for IPsec DOI */

const char *const sit_bit_names[] = {
	"SIT_IDENTITY_ONLY",
	"SIT_SECRECY",
	"SIT_INTEGRITY",
	NULL
};

/* Protocol IDs (RFC 2407 "IPsec DOI" section 4.4.1) */

static const char *const protocol_name[] = {
	"PROTO_ISAKMP",
	"PROTO_IPSEC_AH",
	"PROTO_IPSEC_ESP",
	"PROTO_IPCOMP",
};

enum_names protocol_names =
	{ PROTO_ISAKMP, PROTO_IPCOMP, protocol_name, NULL };

/* IPsec ISAKMP transform values */

static const char *const isakmp_transform_name[] = {
	"KEY_IKE",
};

enum_names isakmp_transformid_names =
	{ KEY_IKE, KEY_IKE, isakmp_transform_name, NULL };

/* IPsec AH transform values */

static const char *const ah_transform_name[] = {
	"HMAC_MD5",
	"HMAC_SHA1",
	"DES_MAC",
	"HMAC_SHA2_256",
	"HMAC_SHA2_384",
	"HMAC_SHA2_512",
	"HMAC_RIPEMD",
	"AES_XCBC_96",
	"SIG_RSA",
	"AES_128_GMAC",
	"AES_192_GMAC",
	"AES_256_GMAC"
};

static const char *const ah_transform_name_high[] = {
	"HMAC_SHA2_256_96"
};

enum_names ah_transform_names_high =
	{ AH_SHA2_256_96, AH_SHA2_256_96, ah_transform_name_high, NULL };

enum_names ah_transform_names =
	{ AH_MD5, AH_AES_256_GMAC, ah_transform_name, &ah_transform_names_high };

/* IPsec ESP transform values */

static const char *const esp_transform_name[] = {
	"DES_IV64",
	"DES_CBC",
	"3DES_CBC",
	"RC5_CBC",
	"IDEA_CBC",
	"CAST_CBC",
	"BLOWFISH_CBC",
	"3IDEA",
	"DES_IV32",
	"RC4",
	"NULL",
	"AES_CBC",
	"AES_CTR",
	"AES_CCM_8",
	"AES_CCM_12",
	"AES_CCM_16",
	"UNASSIGNED_17",
	"AES_GCM_8",
	"AES_GCM_12",
	"AES_GCM_16",
	"SEED_CBC",
	"CAMELLIA_CBC",
	"AES_GMAC"
};

static const char *const esp_transform_name_high[] = {
	"SERPENT_CBC",
	"TWOFISH_CBC"
};

enum_names esp_transform_names_high =
	{ ESP_SERPENT, ESP_TWOFISH, esp_transform_name_high, NULL };

enum_names esp_transform_names =
	{ ESP_DES_IV64, ESP_AES_GMAC, esp_transform_name, &esp_transform_names_high };

/* IPCOMP transform values */

static const char *const ipcomp_transform_name[] = {
	"IPCOMP_OUI",
	"IPCOMP_DEFLATE",
	"IPCOMP_LZS",
	"IPCOMP_LZJH",
};

enum_names ipcomp_transformid_names =
	{ IPCOMP_OUI, IPCOMP_LZJH, ipcomp_transform_name, NULL };

/* Identification type values */

static const char *const ident_name[] = {
	"ID_IPV4_ADDR",
	"ID_FQDN",
	"ID_USER_FQDN",
	"ID_IPV4_ADDR_SUBNET",
	"ID_IPV6_ADDR",
	"ID_IPV6_ADDR_SUBNET",
	"ID_IPV4_ADDR_RANGE",
	"ID_IPV6_ADDR_RANGE",
	"ID_DER_ASN1_DN",
	"ID_DER_ASN1_GN",
	"ID_KEY_ID",
};

enum_names ident_names =
	{ ID_IPV4_ADDR, ID_KEY_ID, ident_name, NULL };

/* Certificate type values */

static const char *const cert_type_name[] = {
	"CERT_NONE",
	"CERT_PKCS7_WRAPPED_X509",
	"CERT_PGP",
	"CERT_DNS_SIGNED_KEY",
	"CERT_X509_SIGNATURE",
	"CERT_X509_KEY_EXCHANGE",
	"CERT_KERBEROS_TOKENS",
	"CERT_CRL",
	"CERT_ARL",
	"CERT_SPKI",
	"CERT_X509_ATTRIBUTE",
};

enum_names cert_type_names =
	{ CERT_NONE, CERT_X509_ATTRIBUTE, cert_type_name, NULL };

/* Certificate policy names */

ENUM(cert_policy_names, CERT_ALWAYS_SEND, CERT_NEVER_SEND,
	"ALWAYS_SEND",
	"SEND_IF_ASKED",
	"NEVER_SEND",
);

/* Goal BITs for establishing an SA
 * Note: we drop the POLICY_ prefix so that logs are more concise.
 */

const char *const sa_policy_bit_names[] = {
	"PSK",
	"PUBKEY",
	"ENCRYPT",
	"AUTHENTICATE",
	"COMPRESS",
	"TUNNEL",
	"PFS",
	"DISABLEARRIVALCHECK",
	"SHUNT0",
	"SHUNT1",
	"FAILSHUNT0",
	"FAILSHUNT1",
	"DONTREKEY",
	"OPPORTUNISTIC",
	"GROUP",
	"GROUTED",
	"UP",
	"MODECFGPUSH",
	"XAUTHPSK",
	"XAUTHRSASIG",
	"XAUTHSERVER",
	"DONTREAUTH",
	"BEET",
	"MOBIKE",
	"PROXY",
	NULL
};

const char *const policy_shunt_names[4] = {
	"TRAP",
	"PASS",
	"DROP",
	"REJECT",
};

const char *const policy_fail_names[4] = {
	"NONE",
	"PASS",
	"DROP",
	"REJECT",
};

/* Oakley transform attributes
 * oakley_attr_bit_names does double duty: it is used for enum names
 * and bit names.
 */

const char *const oakley_attr_bit_names[] = {
	"OAKLEY_ENCRYPTION_ALGORITHM",
	"OAKLEY_HASH_ALGORITHM",
	"OAKLEY_AUTHENTICATION_METHOD",
	"OAKLEY_GROUP_DESCRIPTION",
	"OAKLEY_GROUP_TYPE",
	"OAKLEY_GROUP_PRIME",
	"OAKLEY_GROUP_GENERATOR_ONE",
	"OAKLEY_GROUP_GENERATOR_TWO",
	"OAKLEY_GROUP_CURVE_A",
	"OAKLEY_GROUP_CURVE_B",
	"OAKLEY_LIFE_TYPE",
	"OAKLEY_LIFE_DURATION",
	"OAKLEY_PRF",
	"OAKLEY_KEY_LENGTH",
	"OAKLEY_FIELD_SIZE",
	"OAKLEY_GROUP_ORDER",
	"OAKLEY_BLOCK_SIZE",
	NULL
};

static const char *const oakley_var_attr_name[] = {
	"OAKLEY_GROUP_PRIME (variable length)",
	"OAKLEY_GROUP_GENERATOR_ONE (variable length)",
	"OAKLEY_GROUP_GENERATOR_TWO (variable length)",
	"OAKLEY_GROUP_CURVE_A (variable length)",
	"OAKLEY_GROUP_CURVE_B (variable length)",
	NULL,
	"OAKLEY_LIFE_DURATION (variable length)",
	NULL,
	NULL,
	NULL,
	"OAKLEY_GROUP_ORDER (variable length)",
};

static enum_names oakley_attr_desc_tv = {
	OAKLEY_ENCRYPTION_ALGORITHM + ISAKMP_ATTR_AF_TV,
	OAKLEY_GROUP_ORDER + ISAKMP_ATTR_AF_TV, oakley_attr_bit_names, NULL };

enum_names oakley_attr_names = {
	OAKLEY_GROUP_PRIME, OAKLEY_GROUP_ORDER,
	oakley_var_attr_name, &oakley_attr_desc_tv };

/* for each Oakley attribute, which enum_names describes its values? */
enum_names *oakley_attr_val_descs[] = {
	NULL,                   /* (none) */
	&oakley_enc_names,      /* OAKLEY_ENCRYPTION_ALGORITHM */
	&oakley_hash_names,     /* OAKLEY_HASH_ALGORITHM */
	&oakley_auth_names,     /* OAKLEY_AUTHENTICATION_METHOD */
	&oakley_group_names,    /* OAKLEY_GROUP_DESCRIPTION */
	&oakley_group_type_names,/* OAKLEY_GROUP_TYPE */
	NULL,                   /* OAKLEY_GROUP_PRIME */
	NULL,                   /* OAKLEY_GROUP_GENERATOR_ONE */
	NULL,                   /* OAKLEY_GROUP_GENERATOR_TWO */
	NULL,                   /* OAKLEY_GROUP_CURVE_A */
	NULL,                   /* OAKLEY_GROUP_CURVE_B */
	&oakley_lifetime_names, /* OAKLEY_LIFE_TYPE */
	NULL,                   /* OAKLEY_LIFE_DURATION */
	&oakley_prf_names,      /* OAKLEY_PRF */
	NULL,                   /* OAKLEY_KEY_LENGTH */
	NULL,                   /* OAKLEY_FIELD_SIZE */
	NULL,                   /* OAKLEY_GROUP_ORDER */
};

/* IPsec DOI attributes (RFC 2407 "IPsec DOI" section 4.5) */

static const char *const ipsec_attr_name[] = {
	"SA_LIFE_TYPE",
	"SA_LIFE_DURATION",
	"GROUP_DESCRIPTION",
	"ENCAPSULATION_MODE",
	"AUTH_ALGORITHM",
	"KEY_LENGTH",
	"KEY_ROUNDS",
	"COMPRESS_DICT_SIZE",
	"COMPRESS_PRIVATE_ALG",
};

static const char *const ipsec_var_attr_name[] = {
	"SA_LIFE_DURATION (variable length)",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"COMPRESS_PRIVATE_ALG (variable length)",
};

static enum_names ipsec_attr_desc_tv = {
	SA_LIFE_TYPE + ISAKMP_ATTR_AF_TV,
	COMPRESS_PRIVATE_ALG + ISAKMP_ATTR_AF_TV,
	ipsec_attr_name, NULL };

enum_names ipsec_attr_names = {
	SA_LIFE_DURATION, COMPRESS_PRIVATE_ALG,
	ipsec_var_attr_name, &ipsec_attr_desc_tv };

/* for each IPsec attribute, which enum_names describes its values? */
enum_names *ipsec_attr_val_descs[] = {
	NULL,                   /* (none) */
	&sa_lifetime_names,     /* SA_LIFE_TYPE */
	NULL,                   /* SA_LIFE_DURATION */
	&oakley_group_names,    /* GROUP_DESCRIPTION */
	&enc_mode_names,                /* ENCAPSULATION_MODE */
	&auth_alg_names,                /* AUTH_ALGORITHM */
	NULL,                   /* KEY_LENGTH */
	NULL,                   /* KEY_ROUNDS */
	NULL,                   /* COMPRESS_DICT_SIZE */
	NULL,                   /* COMPRESS_PRIVATE_ALG */
};

/* SA Lifetime Type attribute */

static const char *const sa_lifetime_name[] = {
	"SA_LIFE_TYPE_SECONDS",
	"SA_LIFE_TYPE_KBYTES",
};

enum_names sa_lifetime_names =
	{ SA_LIFE_TYPE_SECONDS, SA_LIFE_TYPE_KBYTES, sa_lifetime_name, NULL };

/* Encapsulation Mode attribute */

static const char *const enc_mode_name[] = {
	"ENCAPSULATION_MODE_TUNNEL",
	"ENCAPSULATION_MODE_TRANSPORT",
	"ENCAPSULATION_MODE_UDP_TUNNEL",
	"ENCAPSULATION_MODE_UDP_TRANSPORT",
};

static const char *const enc_udp_mode_name[] = {
		"ENCAPSULATION_MODE_UDP_TUNNEL",
		"ENCAPSULATION_MODE_UDP_TRANSPORT",
	};

static enum_names enc_udp_mode_names =
	{ ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS, ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS, enc_udp_mode_name, NULL };

enum_names enc_mode_names =
	{ ENCAPSULATION_MODE_TUNNEL, ENCAPSULATION_MODE_UDP_TRANSPORT_RFC, enc_mode_name, &enc_udp_mode_names };

/* Auth Algorithm attribute */

static const char *const auth_alg_name[] = {
    "AUTH_NONE",
	"HMAC_MD5",
	"HMAC_SHA1",
	"DES_MAC",
	"KPDK",
	"HMAC_SHA2_256",
	"HMAC_SHA2_384",
	"HMAC_SHA2_512",
	"HMAC_RIPEMD",
	"AES_XCBC_96",
	"SIG_RSA"
};

static const char *const extended_auth_alg_name[] = {
	"NULL",
	"HMAC_SHA2_256_96"
};

enum_names extended_auth_alg_names =
	{ AUTH_ALGORITHM_NULL, AUTH_ALGORITHM_HMAC_SHA2_256_96,
		extended_auth_alg_name, NULL };

enum_names auth_alg_names =
	{ AUTH_ALGORITHM_NONE, AUTH_ALGORITHM_SIG_RSA,
		auth_alg_name, &extended_auth_alg_names };

/* From draft-beaulieu-ike-xauth */
static const char *const xauth_type_name[] = {
	"Generic",
	"RADIUS-CHAP",
	"OTP",
	"S/KEY",
};

enum_names xauth_type_names =
	{ XAUTH_TYPE_GENERIC, XAUTH_TYPE_SKEY, xauth_type_name, NULL};

/* From draft-beaulieu-ike-xauth */
static const char *const xauth_attr_tv_name[] = {
	"XAUTH_TYPE",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"XAUTH_STATUS",
};

enum_names xauth_attr_tv_names = {
	XAUTH_TYPE   + ISAKMP_ATTR_AF_TV,
	XAUTH_STATUS + ISAKMP_ATTR_AF_TV, xauth_attr_tv_name, NULL };

static const char *const unity_attr_name[] = {
	"UNITY_BANNER",
	"UNITY_SAVE_PASSWD",
	"UNITY_DEF_DOMAIN",
	"UNITY_SPLITDNS_NAME",
	"UNITY_SPLIT_INCLUDE",
	"UNITY_NATT_PORT",
	"UNITY_LOCAL_LAN",
	"UNITY_PFS",
	"UNITY_FW_TYPE",
	"UNITY_BACKUP_SERVERS",
	"UNITY_DDNS_HOSTNAME",
};

enum_names unity_attr_names =
	{ UNITY_BANNER , UNITY_DDNS_HOSTNAME, unity_attr_name , &xauth_attr_tv_names };

static const char *const microsoft_attr_name[] = {
	"INTERNAL_IP4_SERVER",
	"INTERNAL_IP6_SERVER",
};

enum_names microsoft_attr_names =
	{ INTERNAL_IP4_SERVER, INTERNAL_IP6_SERVER, microsoft_attr_name , &unity_attr_names };

static const char *const xauth_attr_name[] = {
	"XAUTH_USER_NAME",
	"XAUTH_USER_PASSWORD",
	"XAUTH_PASSCODE",
	"XAUTH_MESSAGE",
	"XAUTH_CHALLENGE",
	"XAUTH_DOMAIN",
	"XAUTH_STATUS (wrong TLV syntax, should be TV)",
	"XAUTH_NEXT_PIN",
	"XAUTH_ANSWER",
};

enum_names xauth_attr_names =
	{ XAUTH_USER_NAME , XAUTH_ANSWER, xauth_attr_name , &microsoft_attr_names };

static const char *const modecfg_attr_name[] = {
	"INTERNAL_IP4_ADDRESS",
	"INTERNAL_IP4_NETMASK",
	"INTERNAL_IP4_DNS",
	"INTERNAL_IP4_NBNS",
	"INTERNAL_ADDRESS_EXPIRY",
	"INTERNAL_IP4_DHCP",
	"APPLICATION_VERSION",
	"INTERNAL_IP6_ADDRESS",
	"INTERNAL_IP6_NETMASK",
	"INTERNAL_IP6_DNS",
	"INTERNAL_IP6_NBNS",
	"INTERNAL_IP6_DHCP",
	"INTERNAL_IP4_SUBNET",
	"SUPPORTED_ATTRIBUTES",
	"INTERNAL_IP6_SUBNET",
};

enum_names modecfg_attr_names =
	{ INTERNAL_IP4_ADDRESS, INTERNAL_IP6_SUBNET, modecfg_attr_name , &xauth_attr_names };

/* Oakley Lifetime Type attribute */

static const char *const oakley_lifetime_name[] = {
	"OAKLEY_LIFE_SECONDS",
	"OAKLEY_LIFE_KILOBYTES",
};

enum_names oakley_lifetime_names =
	{ OAKLEY_LIFE_SECONDS, OAKLEY_LIFE_KILOBYTES, oakley_lifetime_name, NULL };

/* Oakley PRF attribute (none defined) */

enum_names oakley_prf_names =
	{ 1, 0, NULL, NULL };

/* Oakley Encryption Algorithm attribute */

static const char *const oakley_enc_name[] = {
	"DES_CBC",
	"IDEA_CBC",
	"BLOWFISH_CBC",
	"RC5_R16_B64_CBC",
	"3DES_CBC",
	"CAST_CBC",
	"AES_CBC",
	"CAMELLIA_CBC"
};

#ifdef NO_EXTRA_IKE
enum_names oakley_enc_names =
	{ OAKLEY_DES_CBC, OAKLEY_CAMELLIA_CBC, oakley_enc_name, NULL };
#else
static const char *const oakley_enc_name_draft_aes_cbc_02[] = {
	"MARS_CBC"       /*      65001   */,
	"RC6_CBC"        /*      65002   */,
	"ID_65003"       /*      65003   */,
	"SERPENT_CBC"    /*      65004   */,
	"TWOFISH_CBC"    /*      65005   */,
};

static const char *const oakley_enc_name_ssh[] = {
	"TWOFISH_CBC_SSH",
};

enum_names oakley_enc_names_ssh =
	{ OAKLEY_TWOFISH_CBC_SSH, OAKLEY_TWOFISH_CBC_SSH, oakley_enc_name_ssh
		, NULL };

enum_names oakley_enc_names_draft_aes_cbc_02 =
	{ OAKLEY_MARS_CBC, OAKLEY_TWOFISH_CBC, oakley_enc_name_draft_aes_cbc_02
		, &oakley_enc_names_ssh };

enum_names oakley_enc_names =
	{ OAKLEY_DES_CBC, OAKLEY_CAMELLIA_CBC, oakley_enc_name
		, &oakley_enc_names_draft_aes_cbc_02 };
#endif

/* Oakley Hash Algorithm attribute */

static const char *const oakley_hash_name[] = {
	"HMAC_MD5",
	"HMAC_SHA1",
	"HMAC_TIGER",
	"HMAC_SHA2_256",
	"HMAC_SHA2_384",
	"HMAC_SHA2_512",
};

enum_names oakley_hash_names =
	{ OAKLEY_MD5, OAKLEY_SHA2_512, oakley_hash_name, NULL };

/* Oakley Authentication Method attribute */

static const char *const oakley_auth_name1[] = {
	"pre-shared key",
	"DSS signature",
	"RSA signature",
	"RSA encryption",
	"RSA encryption revised",
	"ElGamal encryption",
	"ELGamal encryption revised",
	"ECDSA signature",
	"ECDSA-256 signature",
	"ECDSA-384 signature",
	"ECDSA-521-signature",
};

static const char *const oakley_auth_name2[] = {
	"HybridInitRSA",
	"HybridRespRSA",
	"HybridInitDSS",
	"HybridRespDSS",
};

static const char *const oakley_auth_name3[] = {
	"XAUTHInitPreShared",
	"XAUTHRespPreShared",
	"XAUTHInitDSS",
	"XAUTHRespDSS",
	"XAUTHInitRSA",
	"XAUTHRespRSA",
	"XAUTHInitRSAEncryption",
	"XAUTHRespRSAEncryption",
	"XAUTHInitRSARevisedEncryption",
	"XAUTHRespRSARevisedEncryption",
};

static enum_names oakley_auth_names1 =
	{ OAKLEY_PRESHARED_KEY, OAKLEY_ECDSA_521
		, oakley_auth_name1, NULL };

static enum_names oakley_auth_names2 =
	{ HybridInitRSA, HybridRespDSS
		, oakley_auth_name2, &oakley_auth_names1 };

enum_names oakley_auth_names =
	{ XAUTHInitPreShared, XAUTHRespRSARevisedEncryption
		, oakley_auth_name3, &oakley_auth_names2 };

/* Oakley Group Description attribute */

static const char *const oakley_group_name[] = {
	"MODP_768",
	"MODP_1024",
	"GP_155",
	"GP_185",
	"MODP_1536",
};

static const char *const oakley_group_name_rfc3526[] = {
	"MODP_2048",
	"MODP_3072",
	"MODP_4096",
	"MODP_6144",
	"MODP_8192"
};

static const char *const oakley_group_name_rfc4753[] = {
	"ECP_256",
	"ECP_384",
	"ECP_521"
};

static const char *const oakley_group_name_rfc5114[] = {
	"MODP_1024_160",
	"MODP_2048_224",
	"MODP_2048_256",
	"ECP_192",
	"ECP_224"
};

enum_names oakley_group_names_rfc5114 =
	{ MODP_1024_160, ECP_224_BIT,
			oakley_group_name_rfc5114, NULL };

enum_names oakley_group_names_rfc4753 =
	{ ECP_256_BIT, ECP_521_BIT,
			oakley_group_name_rfc4753, &oakley_group_names_rfc5114 };

enum_names oakley_group_names_rfc3526 =
	{ MODP_2048_BIT, MODP_8192_BIT,
			oakley_group_name_rfc3526, &oakley_group_names_rfc4753 };

enum_names oakley_group_names =
	{ MODP_768_BIT, MODP_1536_BIT,
			oakley_group_name, &oakley_group_names_rfc3526 };

/* Oakley Group Type attribute */

static const char *const oakley_group_type_name[] = {
	"OAKLEY_GROUP_TYPE_MODP",
	"OAKLEY_GROUP_TYPE_ECP",
	"OAKLEY_GROUP_TYPE_EC2N",
};

enum_names oakley_group_type_names =
	{ OAKLEY_GROUP_TYPE_MODP, OAKLEY_GROUP_TYPE_EC2N, oakley_group_type_name, NULL };

/* Notify messages -- error types */

static const char *const notification_name[] = {
	"INVALID_PAYLOAD_TYPE",
	"DOI_NOT_SUPPORTED",
	"SITUATION_NOT_SUPPORTED",
	"INVALID_COOKIE",
	"INVALID_MAJOR_VERSION",
	"INVALID_MINOR_VERSION",
	"INVALID_EXCHANGE_TYPE",
	"INVALID_FLAGS",
	"INVALID_MESSAGE_ID",
	"INVALID_PROTOCOL_ID",
	"INVALID_SPI",
	"INVALID_TRANSFORM_ID",
	"ATTRIBUTES_NOT_SUPPORTED",
	"NO_PROPOSAL_CHOSEN",
	"BAD_PROPOSAL_SYNTAX",
	"PAYLOAD_MALFORMED",
	"INVALID_KEY_INFORMATION",
	"INVALID_ID_INFORMATION",
	"INVALID_CERT_ENCODING",
	"INVALID_CERTIFICATE",
	"CERT_TYPE_UNSUPPORTED",
	"INVALID_CERT_AUTHORITY",
	"INVALID_HASH_INFORMATION",
	"AUTHENTICATION_FAILED",
	"INVALID_SIGNATURE",
	"ADDRESS_NOTIFICATION",
	"NOTIFY_SA_LIFETIME",
	"CERTIFICATE_UNAVAILABLE",
	"UNSUPPORTED_EXCHANGE_TYPE",
	"UNEQUAL_PAYLOAD_LENGTHS",
};

static const char *const notification_status_name[] = {
	"CONNECTED",
};

static const char *const ipsec_notification_name[] = {
	"IPSEC_RESPONDER_LIFETIME",
	"IPSEC_REPLAY_STATUS",
	"IPSEC_INITIAL_CONTACT",
};

static const char *const notification_dpd_name[] = {
	"R_U_THERE",
	"R_U_THERE_ACK",
};

static const char *const notification_juniper_name[] = {
	"NS_NHTB_INFORM",
};

enum_names notification_juniper_names =
	{ NS_NHTB_INFORM, NS_NHTB_INFORM,
		notification_juniper_name, NULL };

enum_names notification_dpd_names =
	{ R_U_THERE, R_U_THERE_ACK,
		notification_dpd_name, &notification_juniper_names };

enum_names ipsec_notification_names =
	{ IPSEC_RESPONDER_LIFETIME, IPSEC_INITIAL_CONTACT,
		ipsec_notification_name, &notification_dpd_names };

enum_names notification_status_names =
	{ ISAKMP_CONNECTED, ISAKMP_CONNECTED,
		notification_status_name, &ipsec_notification_names };

enum_names notification_names =
	{ ISAKMP_INVALID_PAYLOAD_TYPE, ISAKMP_UNEQUAL_PAYLOAD_LENGTHS,
		notification_name, &notification_status_names };

/* MODECFG
 * From draft-dukes-ike-mode-cfg
 */
const char *const attr_msg_type_name[] = {
	"ISAKMP_CFG_RESERVED",
	"ISAKMP_CFG_REQUEST",
	"ISAKMP_CFG_REPLY",
	"ISAKMP_CFG_SET",
	"ISAKMP_CFG_ACK",
	NULL
};

enum_names attr_msg_type_names =
	{ 0 , ISAKMP_CFG_ACK, attr_msg_type_name , NULL };

/* socket address family info */

static const char *const af_inet_name[] = {
	"AF_INET",
};

static const char *const af_inet6_name[] = {
	"AF_INET6",
};

static enum_names af_names6 = { AF_INET6, AF_INET6, af_inet6_name, NULL };

enum_names af_names = { AF_INET, AF_INET, af_inet_name, &af_names6 };

static ip_address ipv4_any, ipv6_any;
static ip_subnet ipv4_wildcard, ipv6_wildcard;
static ip_subnet ipv4_all, ipv6_all;

const struct af_info af_inet4_info = {
	AF_INET,
	"AF_INET",
	sizeof(struct in_addr),
	sizeof(struct sockaddr_in),
	32,
	ID_IPV4_ADDR, ID_IPV4_ADDR_SUBNET, ID_IPV4_ADDR_RANGE,
	&ipv4_any, &ipv4_wildcard, &ipv4_all,
};

const struct af_info af_inet6_info = {
	AF_INET6,
	"AF_INET6",
	sizeof(struct in6_addr),
	sizeof(struct sockaddr_in6),
	128,
	ID_IPV6_ADDR, ID_IPV6_ADDR_SUBNET, ID_IPV6_ADDR_RANGE,
	&ipv6_any, &ipv6_wildcard, &ipv6_all,
};

const struct af_info *
aftoinfo(int af)
{
	switch (af)
	{
		case AF_INET:
			return &af_inet4_info;
		case AF_INET6:
			return &af_inet6_info;
		default:
			return NULL;
	}
}

bool subnetisnone(const ip_subnet *sn)
{
	ip_address base;

	networkof(sn, &base);
	return isanyaddr(&base) && subnetishost(sn);
}

#ifdef ADNS

/* BIND enumerated types */

#include <arpa/nameser.h>

static const char *const rr_type_name[] = {
	"T_A",  /* 1 host address */
	"T_NS", /* 2 authoritative server */
	"T_MD", /* 3 mail destination */
	"T_MF", /* 4 mail forwarder */
	"T_CNAME",      /* 5 canonical name */
	"T_SOA",        /* 6 start of authority zone */
	"T_MB", /* 7 mailbox domain name */
	"T_MG", /* 8 mail group member */
	"T_MR", /* 9 mail rename name */
	"T_NULL",       /* 10 null resource record */
	"T_WKS",        /* 11 well known service */
	"T_PTR",        /* 12 domain name pointer */
	"T_HINFO",      /* 13 host information */
	"T_MINFO",      /* 14 mailbox information */
	"T_MX", /* 15 mail routing information */
	"T_TXT",        /* 16 text strings */
	"T_RP", /* 17 responsible person */
	"T_AFSDB",      /* 18 AFS cell database */
	"T_X25",        /* 19 X_25 calling address */
	"T_ISDN",       /* 20 ISDN calling address */
	"T_RT", /* 21 router */
	"T_NSAP",       /* 22 NSAP address */
	"T_NSAP_PTR",   /* 23 reverse NSAP lookup (deprecated) */
	"T_SIG",        /* 24 security signature */
	"T_KEY",        /* 25 security key */
	"T_PX", /* 26 X.400 mail mapping */
	"T_GPOS",       /* 27 geographical position (withdrawn) */
	"T_AAAA",       /* 28 IP6 Address */
	"T_LOC",        /* 29 Location Information */
	"T_NXT",        /* 30 Next Valid Name in Zone */
	"T_EID",        /* 31 Endpoint identifier */
	"T_NIMLOC",     /* 32 Nimrod locator */
	"T_SRV",        /* 33 Server selection */
	"T_ATMA",       /* 34 ATM Address */
	"T_NAPTR",      /* 35 Naming Authority PoinTeR */
	NULL
};

enum_names rr_type_names = { T_A, T_NAPTR, rr_type_name, NULL };

/* Query type values which do not appear in resource records */
static const char *const rr_qtype_name[] = {
	"T_IXFR",       /* 251 incremental zone transfer */
	"T_AXFR",       /* 252 transfer zone of authority */
	"T_MAILB",      /* 253 transfer mailbox records */
	"T_MAILA",      /* 254 transfer mail agent records */
	"T_ANY",        /* 255 wildcard match */
	NULL
};

enum_names rr_qtype_names = { T_IXFR, T_ANY, rr_qtype_name, &rr_type_names };

static const char *const rr_class_name[] = {
	"C_IN", /* 1 the arpa internet */
	NULL
};

enum_names rr_class_names = { C_IN, C_IN, rr_class_name, NULL };

#endif /* ADNS */

/*
 * NAT-Traversal defines for nat_traveral type from nat_traversal.h
 *
 */
const char *const natt_type_bitnames[] = {
	"draft-ietf-ipsec-nat-t-ike-00/01",    /* 0 */
	"draft-ietf-ipsec-nat-t-ike-02/03",
	"RFC 3947",
	"3",                                   /* 3 */
	"4",   "5",   "6",   "7",
	"8",   "9",   "10",  "11",
	"12",  "13",  "14",  "15",
	"16",  "17",  "18",  "19",
	"20",  "21",  "22",  "23",
	"24",  "25",  "26",  "27",
	"28",  "29",
	"nat is behind me",
	"nat is behind peer"
};

/* look up enum names in an enum_names */

const char* enum_name(enum_names *ed, unsigned long val)
{
	enum_names  *p;

	for (p = ed; p != NULL; p = p->en_next_range)
	{
		if (p->en_first <= val && val <= p->en_last)
			return p->en_names[val - p->en_first];
	}
	return NULL;
}

/* find or construct a string to describe an enum value
 * Result may be in STATIC buffer!
 */
const char *
enum_show(enum_names *ed, unsigned long val)
{
	const char *p = enum_name(ed, val);

	if (p == NULL)
	{
		static char buf[12];    /* only one!  I hope that it is big enough */

		snprintf(buf, sizeof(buf), "%lu??", val);
		p = buf;
	}
	return p;
}


static char bitnamesbuf[200];   /* only one!  I hope that it is big enough! */

int
enum_search(enum_names *ed, const char *str)
{
	enum_names  *p;
	const char *ptr;
	unsigned en;

	for (p = ed; p != NULL; p = p->en_next_range)
	{
		for (en = p->en_first; en <= p->en_last ;en++)
		{
			ptr = p->en_names[en - p->en_first];
			if (ptr == 0)
			{
				continue;
			}
			if (streq(ptr, str))
			{
				return en;
			}
		}
	}
	return -1;
}

/* construct a string to name the bits on in a set
 * Result may be in STATIC buffer!
 * Note: prettypolicy depends on internal details.
 */
const char* bitnamesof(const char *const table[], lset_t val)
{
	char *p = bitnamesbuf;
	lset_t bit;
	const char *const *tp;

	if (val == 0)
		return "none";

	for (tp = table, bit = 01; val != 0; bit <<= 1)
	{
		if (val & bit)
		{
			const char *n = *tp;
			size_t nl;

			if (n == NULL || *n == '\0')
			{
				/* no name for this bit, so use hex */
				static char flagbuf[sizeof("0x80000000")];

				snprintf(flagbuf, sizeof(flagbuf), "0x%llx", bit);
				n = flagbuf;
			}

			nl = strlen(n);

			if (p != bitnamesbuf && p < bitnamesbuf+sizeof(bitnamesbuf) - 1)
				*p++ = '+';

			if (bitnamesbuf+sizeof(bitnamesbuf) - p > (ptrdiff_t)nl)
			{
				strcpy(p, n);
				p += nl;
			}
			val -= bit;
		}
		if (*tp != NULL)
			tp++;   /* move on, but not past end */
	}
	*p = '\0';
	return bitnamesbuf;
}

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */
const char* prettypolicy(lset_t policy)
{
	const char *bn = bitnamesof(sa_policy_bit_names
		, policy & ~(POLICY_SHUNT_MASK | POLICY_FAIL_MASK));
	size_t len;
	lset_t shunt = (policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT;
	lset_t fail = (policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT;

	if (bn != bitnamesbuf)
		bitnamesbuf[0] = '\0';
	len = strlen(bitnamesbuf);
	if (shunt != 0)
	{
		snprintf(bitnamesbuf + len, sizeof(bitnamesbuf) - len, "+%s"
			, policy_shunt_names[shunt]);
		len += strlen(bitnamesbuf + len);
	}
	if (fail != 0)
	{
		snprintf(bitnamesbuf + len, sizeof(bitnamesbuf) - len, "+failure%s"
			, policy_fail_names[fail]);
		len += strlen(bitnamesbuf + len);
	}
	if (NEVER_NEGOTIATE(policy))
	{
		snprintf(bitnamesbuf + len, sizeof(bitnamesbuf) - len, "+NEVER_NEGOTIATE");
		len += strlen(bitnamesbuf + len);
	}
	return bitnamesbuf;
}

/* test a set by seeing if all bits have names */

bool testset(const char *const table[], lset_t val)
{
	lset_t bit;
	const char *const *tp;

	for (tp = table, bit = 01; val != 0; bit <<= 1, tp++)
	{
		const char *n = *tp;

		if (n == NULL || ((val & bit) && *n == '\0'))
			return FALSE;
		val &= ~bit;
	}
	return TRUE;
}


const char sparse_end[] = "end of sparse names";

/* look up enum names in a sparse_names */
const char *sparse_name(sparse_names sd, unsigned long val)
{
	const struct sparse_name *p;

	for (p = sd; p->name != sparse_end; p++)
		if (p->val == val)
			return p->name;
	return NULL;
}

/* find or construct a string to describe an sparse value
 * Result may be in STATIC buffer!
 */
const char* sparse_val_show(sparse_names sd, unsigned long val)
{
	const char *p = sparse_name(sd, val);

	if (p == NULL)
	{
		static char buf[12];    /* only one!  I hope that it is big enough */

		snprintf(buf, sizeof(buf), "%lu??", val);
		p = buf;
	}
	return p;
}

void init_constants(void)
{
	happy(anyaddr(AF_INET, &ipv4_any));
	happy(anyaddr(AF_INET6, &ipv6_any));

	happy(addrtosubnet(&ipv4_any, &ipv4_wildcard));
	happy(addrtosubnet(&ipv6_any, &ipv6_wildcard));

	happy(initsubnet(&ipv4_any, 0, '0', &ipv4_all));
	happy(initsubnet(&ipv6_any, 0, '0', &ipv6_all));
}

u_char secret_of_the_day[HASH_SIZE_SHA1];


