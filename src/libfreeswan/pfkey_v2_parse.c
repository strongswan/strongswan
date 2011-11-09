/*
 * RFC2367 PF_KEYv2 Key management API message parser
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs.
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
 *		Template from klips/net/ipsec/ipsec/ipsec_parser.c.
 */

char pfkey_v2_parse_c_version[] = "";

# include <sys/types.h>
# include <sys/socket.h>
# include <errno.h>

# include <freeswan.h>
# include <constants.h>
# include <defs.h>  /* for PRINTF_LIKE */
# include <log.h>  /* for debugging and DBG_log */

# ifdef PLUTO
#  define DEBUGGING(level, args...)  { DBG_log("pfkey_lib_debug:" args);  }
# else
#  define DEBUGGING(level, args...)  if(pfkey_lib_debug & level) { printf("pfkey_lib_debug:" args); } else { ; }
# endif

#include <pfkeyv2.h>
#include <pfkey.h>


#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

static struct {
	uint8_t proto;
	uint8_t satype;
	char* name;
} satype_tbl[] = {
	{ SA_ESP,	SADB_SATYPE_ESP,	"ESP"  },
	{ SA_AH,	SADB_SATYPE_AH,		"AH"   },
	{ SA_IPIP,	SADB_X_SATYPE_IPIP,	"IPIP" },
	{ SA_COMP,	SADB_X_SATYPE_COMP,	"COMP" },
	{ SA_INT,	SADB_X_SATYPE_INT,	"INT" },
	{ 0,		0,			"UNKNOWN" }
};

uint8_t
satype2proto(uint8_t satype)
{
	int i =0;

	while(satype_tbl[i].satype != satype && satype_tbl[i].satype != 0) {
		i++;
	}
	return satype_tbl[i].proto;
}

uint8_t
proto2satype(uint8_t proto)
{
	int i = 0;

	while(satype_tbl[i].proto != proto && satype_tbl[i].proto != 0) {
		i++;
	}
	return satype_tbl[i].satype;
}

char*
satype2name(uint8_t satype)
{
	int i = 0;

	while(satype_tbl[i].satype != satype && satype_tbl[i].satype != 0) {
		i++;
	}
	return satype_tbl[i].name;
}

char*
proto2name(uint8_t proto)
{
	int i = 0;

	while(satype_tbl[i].proto != proto && satype_tbl[i].proto != 0) {
		i++;
	}
	return satype_tbl[i].name;
}

/* Default extension parsers taken from the KLIPS code */

DEBUG_NO_STATIC int
pfkey_sa_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_sa *pfkey_sa = (struct sadb_sa *)pfkey_ext;
#if 0
	struct sadb_sa sav2;
#endif

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		  "pfkey_sa_parse: entry\n");
	/* sanity checks... */
	if(!pfkey_sa) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "NULL pointer passed in.\n");
		SENDERR(EINVAL);
	}

#if 0
	/* check if this structure is short, and if so, fix it up.
	 * XXX this is NOT the way to do things.
	 */
	if(pfkey_sa->sadb_sa_len == sizeof(struct sadb_sa_v1)/IPSEC_PFKEYv2_ALIGN) {

		/* yes, so clear out a temporary structure, and copy first */
		memset(&sav2, 0, sizeof(sav2));
		memcpy(&sav2, pfkey_sa, sizeof(struct sadb_sa_v1));
		sav2.sadb_x_sa_ref=-1;
		sav2.sadb_sa_len = sizeof(struct sadb_sa) / IPSEC_PFKEYv2_ALIGN;

		pfkey_sa = &sav2;
	}
#endif


	if(pfkey_sa->sadb_sa_len != sizeof(struct sadb_sa) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "length wrong pfkey_sa->sadb_sa_len=%d sizeof(struct sadb_sa)=%d.\n",
			  pfkey_sa->sadb_sa_len,
			  (int)sizeof(struct sadb_sa));
		SENDERR(EINVAL);
	}

	if(pfkey_sa->sadb_sa_encrypt > SADB_EALG_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "pfkey_sa->sadb_sa_encrypt=%d > SADB_EALG_MAX=%d.\n",
			  pfkey_sa->sadb_sa_encrypt,
			  SADB_EALG_MAX);
		SENDERR(EINVAL);
	}

	if(pfkey_sa->sadb_sa_auth > SADB_AALG_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "pfkey_sa->sadb_sa_auth=%d > SADB_AALG_MAX=%d.\n",
			  pfkey_sa->sadb_sa_auth,
			  SADB_AALG_MAX);
		SENDERR(EINVAL);
	}

	if(pfkey_sa->sadb_sa_state > SADB_SASTATE_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "state=%d exceeds MAX=%d.\n",
			  pfkey_sa->sadb_sa_state,
			  SADB_SASTATE_MAX);
		SENDERR(EINVAL);
	}

	if(pfkey_sa->sadb_sa_state == SADB_SASTATE_DEAD) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "state=%d is DEAD=%d.\n",
			  pfkey_sa->sadb_sa_state,
			  SADB_SASTATE_DEAD);
		SENDERR(EINVAL);
	}

	if(pfkey_sa->sadb_sa_replay > 64) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "replay window size: %d -- must be 0 <= size <= 64\n",
			  pfkey_sa->sadb_sa_replay);
		SENDERR(EINVAL);
	}

	if(! ((pfkey_sa->sadb_sa_exttype ==  SADB_EXT_SA) ||
	      (pfkey_sa->sadb_sa_exttype ==  SADB_X_EXT_SA2)))
	{
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "unknown exttype=%d, expecting SADB_EXT_SA=%d or SADB_X_EXT_SA2=%d.\n",
			  pfkey_sa->sadb_sa_exttype,
			  SADB_EXT_SA,
			  SADB_X_EXT_SA2);
		SENDERR(EINVAL);
	}

	if((IPSEC_SAREF_NULL != pfkey_sa->sadb_x_sa_ref) && (pfkey_sa->sadb_x_sa_ref >= (1 << IPSEC_SA_REF_TABLE_IDX_WIDTH))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sa_parse: "
			  "SAref=%d must be (SAref == IPSEC_SAREF_NULL(%d) || SAref < IPSEC_SA_REF_TABLE_NUM_ENTRIES(%d)).\n",
			  pfkey_sa->sadb_x_sa_ref,
			  IPSEC_SAREF_NULL,
			  IPSEC_SA_REF_TABLE_NUM_ENTRIES);
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_sa_parse: "
		  "successfully found len=%d exttype=%d(%s) spi=%08lx replay=%d state=%d auth=%d encrypt=%d flags=%d ref=%d.\n",
		  pfkey_sa->sadb_sa_len,
		  pfkey_sa->sadb_sa_exttype,
		  pfkey_v2_sadb_ext_string(pfkey_sa->sadb_sa_exttype),
		  (long unsigned int)ntohl(pfkey_sa->sadb_sa_spi),
		  pfkey_sa->sadb_sa_replay,
		  pfkey_sa->sadb_sa_state,
		  pfkey_sa->sadb_sa_auth,
		  pfkey_sa->sadb_sa_encrypt,
		  pfkey_sa->sadb_sa_flags,
		  pfkey_sa->sadb_x_sa_ref);

 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_lifetime_parse(struct sadb_ext  *pfkey_ext)
{
	int error = 0;
	struct sadb_lifetime *pfkey_lifetime = (struct sadb_lifetime *)pfkey_ext;

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		  "pfkey_lifetime_parse:enter\n");
	/* sanity checks... */
	if(!pfkey_lifetime) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_lifetime_parse: "
			  "NULL pointer passed in.\n");
		SENDERR(EINVAL);
	}

	if(pfkey_lifetime->sadb_lifetime_len !=
	   sizeof(struct sadb_lifetime) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_lifetime_parse: "
			  "length wrong pfkey_lifetime->sadb_lifetime_len=%d sizeof(struct sadb_lifetime)=%d.\n",
			  pfkey_lifetime->sadb_lifetime_len,
			  (int)sizeof(struct sadb_lifetime));
		SENDERR(EINVAL);
	}

	if((pfkey_lifetime->sadb_lifetime_exttype != SADB_EXT_LIFETIME_HARD) &&
	   (pfkey_lifetime->sadb_lifetime_exttype != SADB_EXT_LIFETIME_SOFT) &&
	   (pfkey_lifetime->sadb_lifetime_exttype != SADB_EXT_LIFETIME_CURRENT)) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_lifetime_parse: "
			  "unexpected ext_type=%d.\n",
			  pfkey_lifetime->sadb_lifetime_exttype);
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_lifetime_parse: "
		  "life_type=%d(%s) alloc=%u bytes=%u add=%u use=%u pkts=%u.\n",
		  pfkey_lifetime->sadb_lifetime_exttype,
		  pfkey_v2_sadb_ext_string(pfkey_lifetime->sadb_lifetime_exttype),
		  pfkey_lifetime->sadb_lifetime_allocations,
		  (unsigned)pfkey_lifetime->sadb_lifetime_bytes,
		  (unsigned)pfkey_lifetime->sadb_lifetime_addtime,
		  (unsigned)pfkey_lifetime->sadb_lifetime_usetime,
		  pfkey_lifetime->sadb_x_lifetime_packets);
errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_address_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	int saddr_len = 0;
	struct sadb_address *pfkey_address = (struct sadb_address *)pfkey_ext;
	struct sockaddr* s = (struct sockaddr*)((char*)pfkey_address + sizeof(*pfkey_address));
	char ipaddr_txt[ADDRTOT_BUF];

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_address_parse:enter\n");
	/* sanity checks... */
	if(!pfkey_address) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_address_parse: "
			"NULL pointer passed in.\n");
		SENDERR(EINVAL);
	}

	if(pfkey_address->sadb_address_len <
	   (sizeof(struct sadb_address) + sizeof(struct sockaddr))/
	   IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_address_parse: "
			  "size wrong 1 ext_len=%d, adr_ext_len=%d, saddr_len=%d.\n",
			  pfkey_address->sadb_address_len,
			  (int)sizeof(struct sadb_address),
			  (int)sizeof(struct sockaddr));
		SENDERR(EINVAL);
	}

	if(pfkey_address->sadb_address_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_address_parse: "
			  "res=%d, must be zero.\n",
			  pfkey_address->sadb_address_reserved);
		SENDERR(EINVAL);
	}

	switch(pfkey_address->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_EXT_ADDRESS_PROXY:
	case SADB_X_EXT_ADDRESS_DST2:
	case SADB_X_EXT_ADDRESS_SRC_FLOW:
	case SADB_X_EXT_ADDRESS_DST_FLOW:
	case SADB_X_EXT_ADDRESS_SRC_MASK:
	case SADB_X_EXT_ADDRESS_DST_MASK:
	case SADB_X_EXT_NAT_T_OA:
		break;
	default:
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_address_parse: "
			"unexpected ext_type=%d.\n",
			pfkey_address->sadb_address_exttype);
		SENDERR(EINVAL);
	}

	switch(s->sa_family) {
	case AF_INET:
		saddr_len = sizeof(struct sockaddr_in);
		sprintf(ipaddr_txt, "%d.%d.%d.%d"
			, (((struct sockaddr_in*)s)->sin_addr.s_addr >>  0) & 0xFF
			, (((struct sockaddr_in*)s)->sin_addr.s_addr >>  8) & 0xFF
			, (((struct sockaddr_in*)s)->sin_addr.s_addr >> 16) & 0xFF
			, (((struct sockaddr_in*)s)->sin_addr.s_addr >> 24) & 0xFF);
		DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
			  "pfkey_address_parse: "
			  "found exttype=%u(%s) family=%d(AF_INET) address=%s proto=%u port=%u.\n",
			  pfkey_address->sadb_address_exttype,
			  pfkey_v2_sadb_ext_string(pfkey_address->sadb_address_exttype),
			  s->sa_family,
			  ipaddr_txt,
			  pfkey_address->sadb_address_proto,
			  ntohs(((struct sockaddr_in*)s)->sin_port));
		break;
	case AF_INET6:
		saddr_len = sizeof(struct sockaddr_in6);
		sprintf(ipaddr_txt, "%x:%x:%x:%x:%x:%x:%x:%x"
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[0])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[1])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[2])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[3])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[4])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[5])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[6])
			, ntohs(((struct sockaddr_in6*)s)->sin6_addr.s6_addr[7]));
		DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
			  "pfkey_address_parse: "
			  "found exttype=%u(%s) family=%d(AF_INET6) address=%s proto=%u port=%u.\n",
			  pfkey_address->sadb_address_exttype,
			  pfkey_v2_sadb_ext_string(pfkey_address->sadb_address_exttype),
			  s->sa_family,
			  ipaddr_txt,
			  pfkey_address->sadb_address_proto,
			  ((struct sockaddr_in6*)s)->sin6_port);
		break;
	default:
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_address_parse: "
			"s->sa_family=%d not supported.\n",
			s->sa_family);
		SENDERR(EPFNOSUPPORT);
	}

	if(pfkey_address->sadb_address_len !=
	   DIVUP(sizeof(struct sadb_address) + saddr_len, IPSEC_PFKEYv2_ALIGN)) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_address_parse: "
			  "size wrong 2 ext_len=%d, adr_ext_len=%d, saddr_len=%d.\n",
			  pfkey_address->sadb_address_len,
			  (int)sizeof(struct sadb_address),
			  saddr_len);
		SENDERR(EINVAL);
	}

	if(pfkey_address->sadb_address_prefixlen != 0) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_address_parse: "
			"address prefixes not supported yet.\n");
		SENDERR(EAFNOSUPPORT); /* not supported yet */
	}

	/* XXX check if port!=0 */

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_address_parse: successful.\n");
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_key_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_key *pfkey_key = (struct sadb_key *)pfkey_ext;

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_key_parse:enter\n");
	/* sanity checks... */

	if(!pfkey_key) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"NULL pointer passed in.\n");
		SENDERR(EINVAL);
	}

	if(pfkey_key->sadb_key_len < sizeof(struct sadb_key) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_key_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_key->sadb_key_len,
			  (int)sizeof(struct sadb_key));
		SENDERR(EINVAL);
	}

	if(!pfkey_key->sadb_key_bits) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"key length set to zero, must be non-zero.\n");
		SENDERR(EINVAL);
	}

	if(pfkey_key->sadb_key_len !=
	   DIVUP(sizeof(struct sadb_key) * OCTETBITS + pfkey_key->sadb_key_bits,
		 PFKEYBITS)) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"key length=%d does not agree with extension length=%d.\n",
			pfkey_key->sadb_key_bits,
			pfkey_key->sadb_key_len);
		SENDERR(EINVAL);
	}

	if(pfkey_key->sadb_key_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"res=%d, must be zero.\n",
			pfkey_key->sadb_key_reserved);
		SENDERR(EINVAL);
	}

	if(! ( (pfkey_key->sadb_key_exttype == SADB_EXT_KEY_AUTH) ||
	       (pfkey_key->sadb_key_exttype == SADB_EXT_KEY_ENCRYPT))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"expecting extension type AUTH or ENCRYPT, got %d.\n",
			pfkey_key->sadb_key_exttype);
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_key_parse: "
		  "success, found len=%d exttype=%d(%s) bits=%d reserved=%d.\n",
		  pfkey_key->sadb_key_len,
		  pfkey_key->sadb_key_exttype,
		  pfkey_v2_sadb_ext_string(pfkey_key->sadb_key_exttype),
		  pfkey_key->sadb_key_bits,
		  pfkey_key->sadb_key_reserved);

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_ident_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_ident *pfkey_ident = (struct sadb_ident *)pfkey_ext;

	/* sanity checks... */
	if(pfkey_ident->sadb_ident_len < sizeof(struct sadb_ident) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_ident_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_ident->sadb_ident_len,
			  (int)sizeof(struct sadb_ident));
		SENDERR(EINVAL);
	}

	if(pfkey_ident->sadb_ident_type > SADB_IDENTTYPE_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_ident_parse: "
			"ident_type=%d out of range, must be less than %d.\n",
			pfkey_ident->sadb_ident_type,
			SADB_IDENTTYPE_MAX);
		SENDERR(EINVAL);
	}

	if(pfkey_ident->sadb_ident_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_ident_parse: "
			"res=%d, must be zero.\n",
			pfkey_ident->sadb_ident_reserved);
		SENDERR(EINVAL);
	}

	/* string terminator/padding must be zero */
	if(pfkey_ident->sadb_ident_len > sizeof(struct sadb_ident) / IPSEC_PFKEYv2_ALIGN) {
		if(*((char*)pfkey_ident + pfkey_ident->sadb_ident_len * IPSEC_PFKEYv2_ALIGN - 1)) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_ident_parse: "
				"string padding must be zero, last is 0x%02x.\n",
				*((char*)pfkey_ident +
				  pfkey_ident->sadb_ident_len * IPSEC_PFKEYv2_ALIGN - 1));
			SENDERR(EINVAL);
		}
	}

	if( ! ((pfkey_ident->sadb_ident_exttype == SADB_EXT_IDENTITY_SRC) ||
	       (pfkey_ident->sadb_ident_exttype == SADB_EXT_IDENTITY_DST))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_key_parse: "
			"expecting extension type IDENTITY_SRC or IDENTITY_DST, got %d.\n",
			pfkey_ident->sadb_ident_exttype);
		SENDERR(EINVAL);
	}

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_sens_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_sens *pfkey_sens = (struct sadb_sens *)pfkey_ext;

	/* sanity checks... */
	if(pfkey_sens->sadb_sens_len < sizeof(struct sadb_sens) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_sens_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_sens->sadb_sens_len,
			  (int)sizeof(struct sadb_sens));
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
		"pfkey_sens_parse: "
		"Sorry, I can't parse exttype=%d yet.\n",
		pfkey_ext->sadb_ext_type);
#if 0
	SENDERR(EINVAL); /* don't process these yet */
#endif

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_prop_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	int i, num_comb;
	struct sadb_prop *pfkey_prop = (struct sadb_prop *)pfkey_ext;
	struct sadb_comb *pfkey_comb = (struct sadb_comb *)((char*)pfkey_ext + sizeof(struct sadb_prop));

	/* sanity checks... */
	if((pfkey_prop->sadb_prop_len < sizeof(struct sadb_prop) / IPSEC_PFKEYv2_ALIGN) ||
	   (((pfkey_prop->sadb_prop_len * IPSEC_PFKEYv2_ALIGN) - sizeof(struct sadb_prop)) % sizeof(struct sadb_comb))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_prop_parse: "
			  "size wrong ext_len=%d, prop_ext_len=%d comb_ext_len=%d.\n",
			  pfkey_prop->sadb_prop_len,
			  (int)sizeof(struct sadb_prop),
			  (int)sizeof(struct sadb_comb));
		SENDERR(EINVAL);
	}

	if(pfkey_prop->sadb_prop_replay > 64) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_prop_parse: "
			"replay window size: %d -- must be 0 <= size <= 64\n",
			pfkey_prop->sadb_prop_replay);
		SENDERR(EINVAL);
	}

	for(i=0; i<3; i++) {
		if(pfkey_prop->sadb_prop_reserved[i]) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_prop_parse: "
				"res[%d]=%d, must be zero.\n",
				i, pfkey_prop->sadb_prop_reserved[i]);
			SENDERR(EINVAL);
		}
	}

	num_comb = ((pfkey_prop->sadb_prop_len * IPSEC_PFKEYv2_ALIGN) - sizeof(struct sadb_prop)) / sizeof(struct sadb_comb);

	for(i = 0; i < num_comb; i++) {
		if(pfkey_comb->sadb_comb_auth > SADB_AALG_MAX) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_prop_parse: "
				"pfkey_comb[%d]->sadb_comb_auth=%d > SADB_AALG_MAX=%d.\n",
				i,
				pfkey_comb->sadb_comb_auth,
				SADB_AALG_MAX);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_auth) {
			if(!pfkey_comb->sadb_comb_auth_minbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_auth_minbits=0, fatal.\n",
					i);
				SENDERR(EINVAL);
			}
			if(!pfkey_comb->sadb_comb_auth_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_auth_maxbits=0, fatal.\n",
					i);
				SENDERR(EINVAL);
			}
			if(pfkey_comb->sadb_comb_auth_minbits > pfkey_comb->sadb_comb_auth_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_auth_minbits=%d > maxbits=%d, fatal.\n",
					i,
					pfkey_comb->sadb_comb_auth_minbits,
					pfkey_comb->sadb_comb_auth_maxbits);
				SENDERR(EINVAL);
			}
		} else {
			if(pfkey_comb->sadb_comb_auth_minbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_auth_minbits=%d != 0, fatal.\n",
					i,
					pfkey_comb->sadb_comb_auth_minbits);
				SENDERR(EINVAL);
			}
			if(pfkey_comb->sadb_comb_auth_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_auth_maxbits=%d != 0, fatal.\n",
					i,
					pfkey_comb->sadb_comb_auth_maxbits);
				SENDERR(EINVAL);
			}
		}

		if(pfkey_comb->sadb_comb_encrypt > SADB_EALG_MAX) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_comb_parse: "
				"pfkey_comb[%d]->sadb_comb_encrypt=%d > SADB_EALG_MAX=%d.\n",
				i,
				pfkey_comb->sadb_comb_encrypt,
				SADB_EALG_MAX);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_encrypt) {
			if(!pfkey_comb->sadb_comb_encrypt_minbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_encrypt_minbits=0, fatal.\n",
					i);
				SENDERR(EINVAL);
			}
			if(!pfkey_comb->sadb_comb_encrypt_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_encrypt_maxbits=0, fatal.\n",
					i);
				SENDERR(EINVAL);
			}
			if(pfkey_comb->sadb_comb_encrypt_minbits > pfkey_comb->sadb_comb_encrypt_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_encrypt_minbits=%d > maxbits=%d, fatal.\n",
					i,
					pfkey_comb->sadb_comb_encrypt_minbits,
					pfkey_comb->sadb_comb_encrypt_maxbits);
				SENDERR(EINVAL);
			}
		} else {
			if(pfkey_comb->sadb_comb_encrypt_minbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_encrypt_minbits=%d != 0, fatal.\n",
					i,
					pfkey_comb->sadb_comb_encrypt_minbits);
				SENDERR(EINVAL);
			}
			if(pfkey_comb->sadb_comb_encrypt_maxbits) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_prop_parse: "
					"pfkey_comb[%d]->sadb_comb_encrypt_maxbits=%d != 0, fatal.\n",
					i,
					pfkey_comb->sadb_comb_encrypt_maxbits);
				SENDERR(EINVAL);
			}
		}

		/* XXX do sanity check on flags */

		if(pfkey_comb->sadb_comb_hard_allocations && pfkey_comb->sadb_comb_soft_allocations > pfkey_comb->sadb_comb_hard_allocations) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_prop_parse: "
				  "pfkey_comb[%d]->sadb_comb_soft_allocations=%d > hard_allocations=%d, fatal.\n",
				  i,
				  pfkey_comb->sadb_comb_soft_allocations,
				  pfkey_comb->sadb_comb_hard_allocations);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_hard_bytes && pfkey_comb->sadb_comb_soft_bytes > pfkey_comb->sadb_comb_hard_bytes) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_prop_parse: "
				  "pfkey_comb[%d]->sadb_comb_soft_bytes=%Ld > hard_bytes=%Ld, fatal.\n",
				  i,
				  (unsigned long long int)pfkey_comb->sadb_comb_soft_bytes,
				  (unsigned long long int)pfkey_comb->sadb_comb_hard_bytes);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_hard_addtime && pfkey_comb->sadb_comb_soft_addtime > pfkey_comb->sadb_comb_hard_addtime) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_prop_parse: "
				  "pfkey_comb[%d]->sadb_comb_soft_addtime=%Ld > hard_addtime=%Ld, fatal.\n",
				  i,
				  (unsigned long long int)pfkey_comb->sadb_comb_soft_addtime,
				  (unsigned long long int)pfkey_comb->sadb_comb_hard_addtime);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_hard_usetime && pfkey_comb->sadb_comb_soft_usetime > pfkey_comb->sadb_comb_hard_usetime) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_prop_parse: "
				  "pfkey_comb[%d]->sadb_comb_soft_usetime=%Ld > hard_usetime=%Ld, fatal.\n",
				  i,
				  (unsigned long long int)pfkey_comb->sadb_comb_soft_usetime,
				  (unsigned long long int)pfkey_comb->sadb_comb_hard_usetime);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_x_comb_hard_packets && pfkey_comb->sadb_x_comb_soft_packets > pfkey_comb->sadb_x_comb_hard_packets) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_prop_parse: "
				"pfkey_comb[%d]->sadb_x_comb_soft_packets=%d > hard_packets=%d, fatal.\n",
				i,
				pfkey_comb->sadb_x_comb_soft_packets,
				pfkey_comb->sadb_x_comb_hard_packets);
			SENDERR(EINVAL);
		}

		if(pfkey_comb->sadb_comb_reserved) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_prop_parse: "
				"comb[%d].res=%d, must be zero.\n",
				i,
				pfkey_comb->sadb_comb_reserved);
			SENDERR(EINVAL);
		}
		pfkey_comb++;
	}

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_supported_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	unsigned int i, num_alg;
	struct sadb_supported *pfkey_supported = (struct sadb_supported *)pfkey_ext;
	struct sadb_alg *pfkey_alg = (struct sadb_alg*)((char*)pfkey_ext + sizeof(struct sadb_supported));

	/* sanity checks... */
	if((pfkey_supported->sadb_supported_len <
	   sizeof(struct sadb_supported) / IPSEC_PFKEYv2_ALIGN) ||
	   (((pfkey_supported->sadb_supported_len * IPSEC_PFKEYv2_ALIGN) -
	     sizeof(struct sadb_supported)) % sizeof(struct sadb_alg))) {

		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_supported_parse: "
			  "size wrong ext_len=%d, supported_ext_len=%d alg_ext_len=%d.\n",
			  pfkey_supported->sadb_supported_len,
			  (int)sizeof(struct sadb_supported),
			  (int)sizeof(struct sadb_alg));
		SENDERR(EINVAL);
	}

	if(pfkey_supported->sadb_supported_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_supported_parse: "
			"res=%d, must be zero.\n",
			pfkey_supported->sadb_supported_reserved);
		SENDERR(EINVAL);
	}

	num_alg = ((pfkey_supported->sadb_supported_len * IPSEC_PFKEYv2_ALIGN) - sizeof(struct sadb_supported)) / sizeof(struct sadb_alg);

	for(i = 0; i < num_alg; i++) {
		/* process algo description */
		if(pfkey_alg->sadb_alg_reserved) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_supported_parse: "
				"alg[%d], id=%d, ivlen=%d, minbits=%d, maxbits=%d, res=%d, must be zero.\n",
				i,
				pfkey_alg->sadb_alg_id,
				pfkey_alg->sadb_alg_ivlen,
				pfkey_alg->sadb_alg_minbits,
				pfkey_alg->sadb_alg_maxbits,
				pfkey_alg->sadb_alg_reserved);
			SENDERR(EINVAL);
		}

		/* XXX can alg_id auth/enc be determined from info given?
		   Yes, but OpenBSD's method does not iteroperate with rfc2367.
		   rgb, 2000-04-06 */

		switch(pfkey_supported->sadb_supported_exttype) {
		case SADB_EXT_SUPPORTED_AUTH:
			if(pfkey_alg->sadb_alg_id > SADB_AALG_MAX) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_supported_parse: "
					"alg[%d], alg_id=%d > SADB_AALG_MAX=%d, fatal.\n",
					i,
					pfkey_alg->sadb_alg_id,
					SADB_AALG_MAX);
				SENDERR(EINVAL);
			}
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			if(pfkey_alg->sadb_alg_id > SADB_EALG_MAX) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_supported_parse: "
					"alg[%d], alg_id=%d > SADB_EALG_MAX=%d, fatal.\n",
					i,
					pfkey_alg->sadb_alg_id,
					SADB_EALG_MAX);
				SENDERR(EINVAL);
			}
			break;
		default:
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_supported_parse: "
				"alg[%d], alg_id=%d > SADB_EALG_MAX=%d, fatal.\n",
				i,
				pfkey_alg->sadb_alg_id,
				SADB_EALG_MAX);
			SENDERR(EINVAL);
		}
		pfkey_alg++;
	}

 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_spirange_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_spirange *pfkey_spirange = (struct sadb_spirange *)pfkey_ext;

	/* sanity checks... */
        if(pfkey_spirange->sadb_spirange_len !=
	   sizeof(struct sadb_spirange) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_spirange_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_spirange->sadb_spirange_len,
			  (int)sizeof(struct sadb_spirange));
                SENDERR(EINVAL);
        }

        if(pfkey_spirange->sadb_spirange_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_spirange_parse: "
			"reserved=%d must be set to zero.\n",
			pfkey_spirange->sadb_spirange_reserved);
                SENDERR(EINVAL);
        }

        if(ntohl(pfkey_spirange->sadb_spirange_max) < ntohl(pfkey_spirange->sadb_spirange_min)) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_spirange_parse: "
			"minspi=%08x must be < maxspi=%08x.\n",
			ntohl(pfkey_spirange->sadb_spirange_min),
			ntohl(pfkey_spirange->sadb_spirange_max));
                SENDERR(EINVAL);
        }

	if(ntohl(pfkey_spirange->sadb_spirange_min) <= 255) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_spirange_parse: "
			"minspi=%08x must be > 255.\n",
			ntohl(pfkey_spirange->sadb_spirange_min));
		SENDERR(EEXIST);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_spirange_parse: "
		  "ext_len=%u ext_type=%u(%s) min=%u max=%u res=%u.\n",
		  pfkey_spirange->sadb_spirange_len,
		  pfkey_spirange->sadb_spirange_exttype,
		  pfkey_v2_sadb_ext_string(pfkey_spirange->sadb_spirange_exttype),
		  pfkey_spirange->sadb_spirange_min,
		  pfkey_spirange->sadb_spirange_max,
		  pfkey_spirange->sadb_spirange_reserved);
 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_kmprivate_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_x_kmprivate *pfkey_x_kmprivate = (struct sadb_x_kmprivate *)pfkey_ext;

	/* sanity checks... */
	if(pfkey_x_kmprivate->sadb_x_kmprivate_len <
	   sizeof(struct sadb_x_kmprivate) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_x_kmprivate_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_x_kmprivate->sadb_x_kmprivate_len,
			  (int)sizeof(struct sadb_x_kmprivate));
		SENDERR(EINVAL);
	}

	if(pfkey_x_kmprivate->sadb_x_kmprivate_reserved) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_x_kmprivate_parse: "
			  "reserved=%d must be set to zero.\n",
			  pfkey_x_kmprivate->sadb_x_kmprivate_reserved);
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
		  "pfkey_x_kmprivate_parse: "
		  "Sorry, I can't parse exttype=%d yet.\n",
		  pfkey_ext->sadb_ext_type);
	SENDERR(EINVAL); /* don't process these yet */

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_satype_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	int i;
	struct sadb_x_satype *pfkey_x_satype = (struct sadb_x_satype *)pfkey_ext;

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_x_satype_parse: enter\n");
	/* sanity checks... */
	if(pfkey_x_satype->sadb_x_satype_len !=
	   sizeof(struct sadb_x_satype) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_x_satype_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_x_satype->sadb_x_satype_len,
			  (int)sizeof(struct sadb_x_satype));
		SENDERR(EINVAL);
	}

	if(!pfkey_x_satype->sadb_x_satype_satype) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_x_satype_parse: "
			"satype is zero, must be non-zero.\n");
		SENDERR(EINVAL);
	}

	if(pfkey_x_satype->sadb_x_satype_satype > SADB_SATYPE_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_x_satype_parse: "
			"satype %d > max %d, invalid.\n",
			pfkey_x_satype->sadb_x_satype_satype, SADB_SATYPE_MAX);
		SENDERR(EINVAL);
	}

	if(!(satype2proto(pfkey_x_satype->sadb_x_satype_satype))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_x_satype_parse: "
			"proto lookup from satype=%d failed.\n",
			pfkey_x_satype->sadb_x_satype_satype);
		SENDERR(EINVAL);
	}

	for(i = 0; i < 3; i++) {
		if(pfkey_x_satype->sadb_x_satype_reserved[i]) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_x_satype_parse: "
				"reserved[%d]=%d must be set to zero.\n",
				i, pfkey_x_satype->sadb_x_satype_reserved[i]);
			SENDERR(EINVAL);
		}
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_x_satype_parse: "
		  "len=%u ext=%u(%s) satype=%u(%s) res=%u,%u,%u.\n",
		  pfkey_x_satype->sadb_x_satype_len,
		  pfkey_x_satype->sadb_x_satype_exttype,
		  pfkey_v2_sadb_ext_string(pfkey_x_satype->sadb_x_satype_exttype),
		  pfkey_x_satype->sadb_x_satype_satype,
		  satype2name(pfkey_x_satype->sadb_x_satype_satype),
		  pfkey_x_satype->sadb_x_satype_reserved[0],
		  pfkey_x_satype->sadb_x_satype_reserved[1],
		  pfkey_x_satype->sadb_x_satype_reserved[2]);
errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_ext_debug_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	int i;
	struct sadb_x_debug *pfkey_x_debug = (struct sadb_x_debug *)pfkey_ext;

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_x_debug_parse: enter\n");
	/* sanity checks... */
	if(pfkey_x_debug->sadb_x_debug_len !=
	   sizeof(struct sadb_x_debug) / IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_x_debug_parse: "
			  "size wrong ext_len=%d, key_ext_len=%d.\n",
			  pfkey_x_debug->sadb_x_debug_len,
			  (int)sizeof(struct sadb_x_debug));
		SENDERR(EINVAL);
	}

	for(i = 0; i < 4; i++) {
		if(pfkey_x_debug->sadb_x_debug_reserved[i]) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_x_debug_parse: "
				"reserved[%d]=%d must be set to zero.\n",
				i, pfkey_x_debug->sadb_x_debug_reserved[i]);
			SENDERR(EINVAL);
		}
	}

errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_ext_protocol_parse(struct sadb_ext *pfkey_ext)
{
	int error = 0;
	struct sadb_protocol *p = (struct sadb_protocol *)pfkey_ext;

	DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM, "pfkey_x_protocol_parse:\n");
	/* sanity checks... */

	if (p->sadb_protocol_len != sizeof(*p)/IPSEC_PFKEYv2_ALIGN) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_x_protocol_parse: size wrong ext_len=%d, key_ext_len=%d.\n",
			  p->sadb_protocol_len, (int)sizeof(*p));
		SENDERR(EINVAL);
	}

	if (p->sadb_protocol_reserved2 != 0) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			  "pfkey_protocol_parse: res=%d, must be zero.\n",
			  p->sadb_protocol_reserved2);
		SENDERR(EINVAL);
	}

 errlab:
	return error;
}

DEBUG_NO_STATIC int
pfkey_x_ext_nat_t_type_parse(struct sadb_ext *pfkey_ext)
{
	return 0;
}

DEBUG_NO_STATIC int
pfkey_x_ext_nat_t_port_parse(struct sadb_ext *pfkey_ext)
{
	return 0;
}

#define DEFINEPARSER(NAME) static struct pf_key_ext_parsers_def NAME##_def={NAME, #NAME};

DEFINEPARSER(pfkey_sa_parse);
DEFINEPARSER(pfkey_lifetime_parse);
DEFINEPARSER(pfkey_address_parse);
DEFINEPARSER(pfkey_key_parse);
DEFINEPARSER(pfkey_ident_parse);
DEFINEPARSER(pfkey_sens_parse);
DEFINEPARSER(pfkey_prop_parse);
DEFINEPARSER(pfkey_supported_parse);
DEFINEPARSER(pfkey_spirange_parse);
DEFINEPARSER(pfkey_x_kmprivate_parse);
DEFINEPARSER(pfkey_x_satype_parse);
DEFINEPARSER(pfkey_x_ext_debug_parse);
DEFINEPARSER(pfkey_x_ext_protocol_parse);
DEFINEPARSER(pfkey_x_ext_nat_t_type_parse);
DEFINEPARSER(pfkey_x_ext_nat_t_port_parse);

struct pf_key_ext_parsers_def *ext_default_parsers[]=
{
	NULL,                 /* pfkey_msg_parse, */
	&pfkey_sa_parse_def,
	&pfkey_lifetime_parse_def,
	&pfkey_lifetime_parse_def,
	&pfkey_lifetime_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_key_parse_def,
	&pfkey_key_parse_def,
	&pfkey_ident_parse_def,
	&pfkey_ident_parse_def,
	&pfkey_sens_parse_def,
	&pfkey_prop_parse_def,
	&pfkey_supported_parse_def,
	&pfkey_supported_parse_def,
	&pfkey_spirange_parse_def,
	&pfkey_x_kmprivate_parse_def,
	&pfkey_x_satype_parse_def,
	&pfkey_sa_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_address_parse_def,
	&pfkey_x_ext_debug_parse_def,
	&pfkey_x_ext_protocol_parse_def	,
	&pfkey_x_ext_nat_t_type_parse_def,
	&pfkey_x_ext_nat_t_port_parse_def,
	&pfkey_x_ext_nat_t_port_parse_def,
	&pfkey_address_parse_def
};

int
pfkey_msg_parse(struct sadb_msg *pfkey_msg,
		struct pf_key_ext_parsers_def *ext_parsers[],
		struct sadb_ext *extensions[],
		int dir)
{
	int error = 0;
	int remain;
	struct sadb_ext *pfkey_ext;
	int extensions_seen = 0;

	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		  "pfkey_msg_parse: "
		  "parsing message ver=%d, type=%d(%s), errno=%d, satype=%d(%s), len=%d, res=%d, seq=%d, pid=%d.\n",
		  pfkey_msg->sadb_msg_version,
		  pfkey_msg->sadb_msg_type,
		  pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type),
		  pfkey_msg->sadb_msg_errno,
		  pfkey_msg->sadb_msg_satype,
		  satype2name(pfkey_msg->sadb_msg_satype),
		  pfkey_msg->sadb_msg_len,
		  pfkey_msg->sadb_msg_reserved,
		  pfkey_msg->sadb_msg_seq,
		  pfkey_msg->sadb_msg_pid);

	if(ext_parsers == NULL) ext_parsers = ext_default_parsers;

	pfkey_extensions_init(extensions);

	remain = pfkey_msg->sadb_msg_len;
	remain -= sizeof(struct sadb_msg) / IPSEC_PFKEYv2_ALIGN;

	pfkey_ext = (struct sadb_ext*)((char*)pfkey_msg +
				       sizeof(struct sadb_msg));

	extensions[0] = (struct sadb_ext *) pfkey_msg;


	if(pfkey_msg->sadb_msg_version != PF_KEY_V2) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"not PF_KEY_V2 msg, found %d, should be %d.\n",
			pfkey_msg->sadb_msg_version,
			PF_KEY_V2);
		SENDERR(EINVAL);
	}

	if(!pfkey_msg->sadb_msg_type) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"msg type not set, must be non-zero..\n");
		SENDERR(EINVAL);
	}

	if(pfkey_msg->sadb_msg_type > SADB_MAX) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"msg type=%d > max=%d.\n",
			pfkey_msg->sadb_msg_type,
			SADB_MAX);
		SENDERR(EINVAL);
	}

	switch(pfkey_msg->sadb_msg_type) {
	case SADB_GETSPI:
	case SADB_UPDATE:
	case SADB_ADD:
	case SADB_DELETE:
	case SADB_GET:
	case SADB_X_GRPSA:
	case SADB_X_ADDFLOW:
		if(!satype2proto(pfkey_msg->sadb_msg_satype)) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_msg_parse: "
				  "satype %d conversion to proto failed for msg_type %d (%s).\n",
				  pfkey_msg->sadb_msg_satype,
				  pfkey_msg->sadb_msg_type,
				  pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type));
			SENDERR(EINVAL);
		} else {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_msg_parse: "
				  "satype %d(%s) conversion to proto gives %d for msg_type %d(%s).\n",
				  pfkey_msg->sadb_msg_satype,
				  satype2name(pfkey_msg->sadb_msg_satype),
				  satype2proto(pfkey_msg->sadb_msg_satype),
				  pfkey_msg->sadb_msg_type,
				  pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type));
		}
		/* fall through */
	case SADB_ACQUIRE:
	case SADB_REGISTER:
	case SADB_EXPIRE:
		if(!pfkey_msg->sadb_msg_satype) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				  "pfkey_msg_parse: "
				  "satype is zero, must be non-zero for msg_type %d(%s).\n",
				  pfkey_msg->sadb_msg_type,
				  pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type));
			SENDERR(EINVAL);
		}
	default:
		break;
	}

	/* errno must not be set in downward messages */
	/* this is not entirely true... a response to an ACQUIRE could return an error */
	if((dir == EXT_BITS_IN) && (pfkey_msg->sadb_msg_type != SADB_ACQUIRE) && pfkey_msg->sadb_msg_errno) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			    "pfkey_msg_parse: "
			    "errno set to %d.\n",
			    pfkey_msg->sadb_msg_errno);
		SENDERR(EINVAL);
	}

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		  "pfkey_msg_parse: "
		  "remain=%d, ext_type=%d(%s), ext_len=%d.\n",
		  remain,
		  pfkey_ext->sadb_ext_type,
		  pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
		  pfkey_ext->sadb_ext_len);

	DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
		"pfkey_msg_parse: "
		"extensions permitted=%08x, required=%08x.\n",
		extensions_bitmaps[dir][EXT_BITS_PERM][pfkey_msg->sadb_msg_type],
		extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type]);

	extensions_seen = 1;

	while( (remain * IPSEC_PFKEYv2_ALIGN) >= sizeof(struct sadb_ext) ) {
		/* Is there enough message left to support another extension header? */
		if(remain < pfkey_ext->sadb_ext_len) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"remain %d less than ext len %d.\n",
				remain, pfkey_ext->sadb_ext_len);
			SENDERR(EINVAL);
		}

		DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
			"pfkey_msg_parse: "
			"parsing ext type=%d(%s) remain=%d.\n",
			pfkey_ext->sadb_ext_type,
			pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
			remain);

		/* Is the extension header type valid? */
		if((pfkey_ext->sadb_ext_type > SADB_EXT_MAX) || (!pfkey_ext->sadb_ext_type)) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"ext type %d(%s) invalid, SADB_EXT_MAX=%d.\n",
				pfkey_ext->sadb_ext_type,
				pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
				SADB_EXT_MAX);
			SENDERR(EINVAL);
		}

		/* Have we already seen this type of extension? */
		if((extensions_seen & ( 1 << pfkey_ext->sadb_ext_type )) != 0)
		{
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"ext type %d(%s) already seen.\n",
				pfkey_ext->sadb_ext_type,
				pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type));
			SENDERR(EINVAL);
		}

		/* Do I even know about this type of extension? */
		if(ext_parsers[pfkey_ext->sadb_ext_type]==NULL) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"ext type %d(%s) unknown, ignoring.\n",
				pfkey_ext->sadb_ext_type,
				pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type));
			goto next_ext;
		}

		/* Is this type of extension permitted for this type of message? */
		if(!(extensions_bitmaps[dir][EXT_BITS_PERM][pfkey_msg->sadb_msg_type] &
		     1<<pfkey_ext->sadb_ext_type)) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"ext type %d(%s) not permitted, exts_perm_in=%08x, 1<<type=%08x\n",
				pfkey_ext->sadb_ext_type,
				pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
				extensions_bitmaps[dir][EXT_BITS_PERM][pfkey_msg->sadb_msg_type],
				1<<pfkey_ext->sadb_ext_type);
			SENDERR(EINVAL);
		}

		DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
			  "pfkey_msg_parse: "
			  "remain=%d ext_type=%d(%s) ext_len=%d parsing ext 0p%p with parser %s.\n",
			  remain,
			  pfkey_ext->sadb_ext_type,
			  pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
			  pfkey_ext->sadb_ext_len,
			  pfkey_ext,
			  ext_parsers[pfkey_ext->sadb_ext_type]->parser_name);

		/* Parse the extension */
		if((error =
		    (*ext_parsers[pfkey_ext->sadb_ext_type]->parser)(pfkey_ext))) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"extension parsing for type %d(%s) failed with error %d.\n",
				pfkey_ext->sadb_ext_type,
				pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type),
				error);
			SENDERR(-error);
		}
		DEBUGGING(PF_KEY_DEBUG_PARSE_FLOW,
			"pfkey_msg_parse: "
			"Extension %d(%s) parsed.\n",
			pfkey_ext->sadb_ext_type,
			pfkey_v2_sadb_ext_string(pfkey_ext->sadb_ext_type));

		/* Mark that we have seen this extension and remember the header location */
		extensions_seen |= ( 1 << pfkey_ext->sadb_ext_type );
		extensions[pfkey_ext->sadb_ext_type] = pfkey_ext;

	next_ext:
		/* Calculate how much message remains */
		remain -= pfkey_ext->sadb_ext_len;

		if(!remain) {
			break;
		}
		/* Find the next extension header */
		pfkey_ext = (struct sadb_ext*)((char*)pfkey_ext +
			pfkey_ext->sadb_ext_len * IPSEC_PFKEYv2_ALIGN);
	}

	if(remain) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"unexpected remainder of %d.\n",
			remain);
		/* why is there still something remaining? */
		SENDERR(EINVAL);
	}

	/* check required extensions */
	DEBUGGING(PF_KEY_DEBUG_PARSE_STRUCT,
		"pfkey_msg_parse: "
		"extensions permitted=%08x, seen=%08x, required=%08x.\n",
		extensions_bitmaps[dir][EXT_BITS_PERM][pfkey_msg->sadb_msg_type],
		extensions_seen,
		extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type]);

	/* don't check further if it is an error return message since it
	   may not have a body */
	if(pfkey_msg->sadb_msg_errno) {
		SENDERR(-error);
	}

	if((extensions_seen &
	    extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type]) !=
	   extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type]) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"required extensions missing:%08x.\n",
			extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type] -
			(extensions_seen &
			 extensions_bitmaps[dir][EXT_BITS_REQ][pfkey_msg->sadb_msg_type]));
		SENDERR(EINVAL);
	}

	if((dir == EXT_BITS_IN) && (pfkey_msg->sadb_msg_type == SADB_X_DELFLOW)
	   && ((extensions_seen	& SADB_X_EXT_ADDRESS_DELFLOW)
	       != SADB_X_EXT_ADDRESS_DELFLOW)
	   && (((extensions_seen & (1<<SADB_EXT_SA)) != (1<<SADB_EXT_SA))
	   || ((((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_flags
		& SADB_X_SAFLAGS_CLEARFLOW)
	       != SADB_X_SAFLAGS_CLEARFLOW))) {
		DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
			"pfkey_msg_parse: "
			"required SADB_X_DELFLOW extensions missing: either %08x must be present or %08x must be present with SADB_X_SAFLAGS_CLEARFLOW set.\n",
			SADB_X_EXT_ADDRESS_DELFLOW
			- (extensions_seen & SADB_X_EXT_ADDRESS_DELFLOW),
			(1<<SADB_EXT_SA) - (extensions_seen & (1<<SADB_EXT_SA)));
		SENDERR(EINVAL);
	}

	switch(pfkey_msg->sadb_msg_type) {
	case SADB_ADD:
	case SADB_UPDATE:
		/* check maturity */
		if(((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state !=
		   SADB_SASTATE_MATURE) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"state=%d for add or update should be MATURE=%d.\n",
				((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_state,
				SADB_SASTATE_MATURE);
			SENDERR(EINVAL);
		}

		/* check AH and ESP */
		switch(((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype) {
		case SADB_SATYPE_AH:
			if(!(((struct sadb_sa*)extensions[SADB_EXT_SA]) &&
			     ((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_auth !=
			     SADB_AALG_NONE)) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"auth alg is zero, must be non-zero for AH SAs.\n");
				SENDERR(EINVAL);
			}
			if(((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_encrypt !=
			   SADB_EALG_NONE) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"AH handed encalg=%d, must be zero.\n",
					((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_encrypt);
				SENDERR(EINVAL);
			}
			break;
		case SADB_SATYPE_ESP:
			if(!(((struct sadb_sa*)extensions[SADB_EXT_SA]) &&
			     ((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_encrypt !=
			     SADB_EALG_NONE)) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"encrypt alg=%d is zero, must be non-zero for ESP=%d SAs.\n",
					((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_encrypt,
					((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype);
				SENDERR(EINVAL);
			}
			if((((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_encrypt ==
			    SADB_EALG_NULL) &&
			   (((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_auth ==
			    SADB_AALG_NONE) ) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"ESP handed encNULL+authNONE, illegal combination.\n");
				SENDERR(EINVAL);
			}
			break;
		case SADB_X_SATYPE_COMP:
			if(!(((struct sadb_sa*)extensions[SADB_EXT_SA]) &&
			     ((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_encrypt !=
			     SADB_EALG_NONE)) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"encrypt alg=%d is zero, must be non-zero for COMP=%d SAs.\n",
					((struct sadb_sa*)extensions[SADB_EXT_SA])->sadb_sa_encrypt,
					((struct sadb_msg*)extensions[SADB_EXT_RESERVED])->sadb_msg_satype);
				SENDERR(EINVAL);
			}
			if(((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_auth !=
			   SADB_AALG_NONE) {
				DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
					"pfkey_msg_parse: "
					"COMP handed auth=%d, must be zero.\n",
					((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_auth);
				SENDERR(EINVAL);
			}
			break;
		default:
			break;
		}
		if(ntohl(((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_spi) <= 255) {
			DEBUGGING(PF_KEY_DEBUG_PARSE_PROBLEM,
				"pfkey_msg_parse: "
				"spi=%08x must be > 255.\n",
				ntohl(((struct sadb_sa*)(extensions[SADB_EXT_SA]))->sadb_sa_spi));
			SENDERR(EINVAL);
		}
	default:
		break;
	}
errlab:

	return error;
}
