/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "kernel.h"
#include "log.h"
#include "spdb.h"
#include "whack.h"
#include "crypto.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "nat_traversal.h"

#define AD(x) x, countof(x)     /* Array Description */
#define AD_NULL NULL, 0

/**************** Oakely (main mode) SA database ****************/

/* array of proposals to be conjoined (can only be one for Oakley) */

static struct db_prop oakley_pc[] =
	{ { PROTO_ISAKMP, AD_NULL } };

/* array of proposal conjuncts (can only be one) */

static struct db_prop_conj oakley_props[] = { { AD(oakley_pc) } };

/* the sadb entry */
struct db_sa oakley_sadb = { AD(oakley_props) };

/**************** IPsec (quick mode) SA database ****************/

/* arrays of attributes for transforms */

static struct db_attr espsha1_attr[] = {
	{ AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
	};

static struct db_attr ah_HMAC_SHA1_attr[] = {
	{ AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1 },
	};

/* arrays of transforms, each in in preference order */

static struct db_trans espa_trans[] = {
	{ ESP_3DES, AD(espsha1_attr) },
	};

static struct db_trans esp_trans[] = {
	{ ESP_3DES, AD_NULL },
	};

#ifdef SUPPORT_ESP_NULL
static struct db_trans espnull_trans[] = {
	{ ESP_NULL, AD(espsha1_attr) },
	};
#endif /* SUPPORT_ESP_NULL */

static struct db_trans ah_trans[] = {
	{ AH_SHA, AD(ah_HMAC_SHA1_attr) },
	};

static struct db_trans ipcomp_trans[] = {
	{ IPCOMP_DEFLATE, AD_NULL },
	};

/* arrays of proposals to be conjoined */

static struct db_prop ah_pc[] = {
	{ PROTO_IPSEC_AH, AD(ah_trans) },
	};

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_pc[] = {
	{ PROTO_IPSEC_ESP, AD(espnull_trans) },
	};
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_pc[] = {
	{ PROTO_IPSEC_ESP, AD(espa_trans) },
	};

static struct db_prop ah_esp_pc[] = {
	{ PROTO_IPSEC_AH, AD(ah_trans) },
	{ PROTO_IPSEC_ESP, AD(esp_trans) },
	};

static struct db_prop compress_pc[] = {
	{ PROTO_IPCOMP, AD(ipcomp_trans) },
	};

static struct db_prop ah_compress_pc[] = {
	{ PROTO_IPSEC_AH, AD(ah_trans) },
	{ PROTO_IPCOMP, AD(ipcomp_trans) },
	};

#ifdef SUPPORT_ESP_NULL
static struct db_prop espnull_compress_pc[] = {
	{ PROTO_IPSEC_ESP, AD(espnull_trans) },
	{ PROTO_IPCOMP, AD(ipcomp_trans) },
	};
#endif /* SUPPORT_ESP_NULL */

static struct db_prop esp_compress_pc[] = {
	{ PROTO_IPSEC_ESP, AD(espa_trans) },
	{ PROTO_IPCOMP, AD(ipcomp_trans) },
	};

static struct db_prop ah_esp_compress_pc[] = {
	{ PROTO_IPSEC_AH, AD(ah_trans) },
	{ PROTO_IPSEC_ESP, AD(esp_trans) },
	{ PROTO_IPCOMP, AD(ipcomp_trans) },
	};

/* arrays of proposal alternatives (each element is a conjunction) */

static struct db_prop_conj ah_props[] = {
	{ AD(ah_pc) },
#ifdef SUPPORT_ESP_NULL
	{ AD(espnull_pc) }
#endif
	};

static struct db_prop_conj esp_props[] =
	{ { AD(esp_pc) } };

static struct db_prop_conj ah_esp_props[] =
	{ { AD(ah_esp_pc) } };

static struct db_prop_conj compress_props[] = {
	{ AD(compress_pc) },
	};

static struct db_prop_conj ah_compress_props[] = {
	{ AD(ah_compress_pc) },
#ifdef SUPPORT_ESP_NULL
	{ AD(espnull_compress_pc) }
#endif
	};

static struct db_prop_conj esp_compress_props[] =
	{ { AD(esp_compress_pc) } };

static struct db_prop_conj ah_esp_compress_props[] =
	{ { AD(ah_esp_compress_pc) } };

/* The IPsec sadb is subscripted by a bitset (subset of policy)
 * with members from { POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS }
 * shifted right by POLICY_IPSEC_SHIFT.
 */
struct db_sa ipsec_sadb[1 << 3] = {
	{ AD_NULL },        /* none */
	{ AD(esp_props) },  /* POLICY_ENCRYPT */
	{ AD(ah_props) },   /* POLICY_AUTHENTICATE */
	{ AD(ah_esp_props) },       /* POLICY_ENCRYPT+POLICY_AUTHENTICATE */
	{ AD(compress_props) },     /* POLICY_COMPRESS */
	{ AD(esp_compress_props) }, /* POLICY_ENCRYPT+POLICY_COMPRESS */
	{ AD(ah_compress_props) },  /* POLICY_AUTHENTICATE+POLICY_COMPRESS */
	{ AD(ah_esp_compress_props) },      /* POLICY_ENCRYPT+POLICY_AUTHENTICATE+POLICY_COMPRESS */
	};

#undef AD
#undef AD_NULL

/* output an attribute (within an SA) */
static bool
out_attr(int type
, unsigned long val
, struct_desc *attr_desc
, enum_names **attr_val_descs USED_BY_DEBUG
, pb_stream *pbs)
{
	struct isakmp_attribute attr;

	if (val >> 16 == 0)
	{
		/* short value: use TV form */
		attr.isaat_af_type = type | ISAKMP_ATTR_AF_TV;
		attr.isaat_lv = val;
		if (!out_struct(&attr, attr_desc, pbs, NULL))
			return FALSE;
	}
	else
	{
		/* This is a real fudge!  Since we rarely use long attributes
		 * and since this is the only place where we can cause an
		 * ISAKMP message length to be other than a multiple of 4 octets,
		 * we force the length of the value to be a multiple of 4 octets.
		 * Furthermore, we only handle values up to 4 octets in length.
		 * Voila: a fixed format!
		 */
		pb_stream val_pbs;
		u_int32_t nval = htonl(val);

		attr.isaat_af_type = type | ISAKMP_ATTR_AF_TLV;
		if (!out_struct(&attr, attr_desc, pbs, &val_pbs)
		|| !out_raw(&nval, sizeof(nval), &val_pbs, "long attribute value"))
			return FALSE;
		close_output_pbs(&val_pbs);
	}
	DBG(DBG_EMITTING,
		enum_names *d = attr_val_descs[type];

		if (d != NULL)
			DBG_log("    [%lu is %s]"
				, val, enum_show(d, val)));
	return TRUE;
}
#define return_on(var, val) do { var=val;goto return_out; } while(0)
/* Output an SA, as described by a db_sa.
 * This has the side-effect of allocating SPIs for us.
 */
bool
out_sa(pb_stream *outs
, struct db_sa *sadb
, struct state *st
, bool oakley_mode
, u_int8_t np)
{
	pb_stream sa_pbs;
	int pcn;
	bool ret = FALSE;
	bool ah_spi_generated = FALSE
		, esp_spi_generated = FALSE
		, ipcomp_cpi_generated = FALSE;
#if !defined NO_KERNEL_ALG || !defined NO_IKE_ALG
	struct db_context *db_ctx = NULL;
#endif

	/* SA header out */
	{
		struct isakmp_sa sa;

		sa.isasa_np = np;
		st->st_doi = sa.isasa_doi = ISAKMP_DOI_IPSEC;   /* all we know */
		if (!out_struct(&sa, &isakmp_sa_desc, outs, &sa_pbs))
			return_on(ret, FALSE);
	}

	/* within SA: situation out */
	st->st_situation = SIT_IDENTITY_ONLY;
	if (!out_struct(&st->st_situation, &ipsec_sit_desc, &sa_pbs, NULL))
		return_on(ret, FALSE);

	/* within SA: Proposal Payloads
	 *
	 * Multiple Proposals with the same number are simultaneous
	 * (conjuncts) and must deal with different protocols (AH or ESP).
	 * Proposals with different numbers are alternatives (disjuncts),
	 * in preference order.
	 * Proposal numbers must be monotonic.
	 * See RFC 2408 "ISAKMP" 4.2
	 */

	for (pcn = 0; pcn != sadb->prop_conj_cnt; pcn++)
	{
		struct db_prop_conj *pc = &sadb->prop_conjs[pcn];
		int pn;

		for (pn = 0; pn != pc->prop_cnt; pn++)
		{
			struct db_prop *p = &pc->props[pn];
			pb_stream proposal_pbs;
			struct isakmp_proposal proposal;
			struct_desc *trans_desc = NULL;
			struct_desc *attr_desc = NULL;
			enum_names **attr_val_descs = NULL;
			int tn;
			bool tunnel_mode;

			tunnel_mode = (pn == pc->prop_cnt-1)
				&& (st->st_policy & POLICY_TUNNEL);

			/* Proposal header */
			proposal.isap_np = pcn == sadb->prop_conj_cnt-1 && pn == pc->prop_cnt-1
				? ISAKMP_NEXT_NONE : ISAKMP_NEXT_P;
			proposal.isap_proposal = pcn;
			proposal.isap_protoid = p->protoid;
			proposal.isap_spisize = oakley_mode ? 0
				: p->protoid == PROTO_IPCOMP ? IPCOMP_CPI_SIZE
				: IPSEC_DOI_SPI_SIZE;

			/* In quick mode ONLY, create proposal for runtime kernel algos.
			 *  Replace ESP proposals with runtime created one
			 */
			if (!oakley_mode && p->protoid == PROTO_IPSEC_ESP)
			{
				DBG(DBG_CONTROL | DBG_CRYPT,
					if (st->st_connection->alg_info_esp)
					{
						static char buf[BUF_LEN]="";

						alg_info_snprint(buf, sizeof (buf),
								(struct alg_info *)st->st_connection->alg_info_esp);
						DBG_log("esp proposal: %s", buf);
					}
				)
				db_ctx = kernel_alg_db_new(st->st_connection->alg_info_esp, st->st_policy);
				p = db_prop_get(db_ctx);

				if (!p || p->trans_cnt == 0)
				{
					loglog(RC_LOG_SERIOUS,
						"empty IPSEC SA proposal to send "
						"(no kernel algorithms for esp selection)");
					return_on(ret, FALSE);
				}
			}

			if (oakley_mode && p->protoid == PROTO_ISAKMP)
			{
				DBG(DBG_CONTROL | DBG_CRYPT,
					if (st->st_connection->alg_info_ike)
					{
						static char buf[BUF_LEN]="";

						alg_info_snprint(buf, sizeof (buf),
								(struct alg_info *)st->st_connection->alg_info_ike);
						DBG_log("ike proposal: %s", buf);
					}
				)
				db_ctx = ike_alg_db_new(st->st_connection, st->st_policy);
				p = db_prop_get(db_ctx);

				if (!p || p->trans_cnt == 0)
				{
					loglog(RC_LOG_SERIOUS,
						"empty ISAKMP SA proposal to send "
						"(no algorithms for ike selection?)");
					return_on(ret, FALSE);
				}
			}

			proposal.isap_notrans = p->trans_cnt;
			if (!out_struct(&proposal, &isakmp_proposal_desc, &sa_pbs, &proposal_pbs))
				return_on(ret, FALSE);

			/* Per-protocols stuff:
			 * Set trans_desc.
			 * Set attr_desc.
			 * Set attr_val_descs.
			 * If not oakley_mode, emit SPI.
			 * We allocate SPIs on demand.
			 * All ESPs in an SA will share a single SPI.
			 * All AHs in an SAwill share a single SPI.
			 * AHs' SPI will be distinct from ESPs'.
			 * This latter is needed because KLIPS doesn't
			 * use the protocol when looking up a (dest, protocol, spi).
			 * ??? If multiple ESPs are composed, how should their SPIs
			 * be allocated?
			 */
			{
				ipsec_spi_t *spi_ptr = NULL;
				int proto = 0;
				bool *spi_generated = NULL;

				switch (p->protoid)
				{
				case PROTO_ISAKMP:
					passert(oakley_mode);
					trans_desc = &isakmp_isakmp_transform_desc;
					attr_desc = &isakmp_oakley_attribute_desc;
					attr_val_descs = oakley_attr_val_descs;
					/* no SPI needed */
					break;
				case PROTO_IPSEC_AH:
					passert(!oakley_mode);
					trans_desc = &isakmp_ah_transform_desc;
					attr_desc = &isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;
					spi_ptr = &st->st_ah.our_spi;
					spi_generated = &ah_spi_generated;
					proto = IPPROTO_AH;
					break;
				case PROTO_IPSEC_ESP:
					passert(!oakley_mode);
					trans_desc = &isakmp_esp_transform_desc;
					attr_desc = &isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;
					spi_ptr = &st->st_esp.our_spi;
					spi_generated = &esp_spi_generated;
					proto = IPPROTO_ESP;
					break;
				case PROTO_IPCOMP:
					passert(!oakley_mode);
					trans_desc = &isakmp_ipcomp_transform_desc;
					attr_desc = &isakmp_ipsec_attribute_desc;
					attr_val_descs = ipsec_attr_val_descs;

					/* a CPI isn't quite the same as an SPI
					 * so we use specialized code to emit it.
					 */
					if (!ipcomp_cpi_generated)
					{
						st->st_ipcomp.our_spi = get_my_cpi(
							&st->st_connection->spd, tunnel_mode);
						if (st->st_ipcomp.our_spi == 0)
							return_on(ret, FALSE);      /* problem generating CPI */

						ipcomp_cpi_generated = TRUE;
					}
					/* CPI is stored in network low order end of an
					 * ipsec_spi_t.  So we start a couple of bytes in.
					 */
					if (!out_raw((u_char *)&st->st_ipcomp.our_spi
					 + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
					, IPCOMP_CPI_SIZE
					, &proposal_pbs, "CPI"))
						return_on(ret, FALSE);
					break;
				default:
					bad_case(p->protoid);
				}
				if (spi_ptr != NULL)
				{
					if (!*spi_generated)
					{
						*spi_ptr = get_ipsec_spi(0
							, proto
							, &st->st_connection->spd
							, tunnel_mode);
						if (*spi_ptr == 0)
							return_on(ret, FALSE);
						*spi_generated = TRUE;
					}
					if (!out_raw((u_char *)spi_ptr, IPSEC_DOI_SPI_SIZE
					, &proposal_pbs, "SPI"))
						return_on(ret, FALSE);
				}
			}

			/* within proposal: Transform Payloads */
			for (tn = 0; tn != p->trans_cnt; tn++)
			{
				struct db_trans *t = &p->trans[tn];
				pb_stream trans_pbs;
				struct isakmp_transform trans;
				int an;

				trans.isat_np = (tn == p->trans_cnt - 1)
					? ISAKMP_NEXT_NONE : ISAKMP_NEXT_T;
				trans.isat_transnum = tn;
				trans.isat_transid = t->transid;
				if (!out_struct(&trans, trans_desc, &proposal_pbs, &trans_pbs))
					return_on(ret, FALSE);

				/* Within transform: Attributes. */

				/* For Phase 2 / Quick Mode, GROUP_DESCRIPTION is
				 * automatically generated because it must be the same
				 * in every transform.  Except IPCOMP.
				 */
				if (p->protoid != PROTO_IPCOMP && st->st_pfs_group != NULL)
				{
					passert(!oakley_mode);
					passert(st->st_pfs_group != &unset_group);
					out_attr(GROUP_DESCRIPTION, st->st_pfs_group->algo_id
						, attr_desc, attr_val_descs
						, &trans_pbs);
				}

				/* automatically generate duration
				 * and, for Phase 2 / Quick Mode, encapsulation.
				 */
				if (oakley_mode)
				{
					out_attr(OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS
						, attr_desc, attr_val_descs
						, &trans_pbs);
					out_attr(OAKLEY_LIFE_DURATION
						, st->st_connection->sa_ike_life_seconds
						, attr_desc, attr_val_descs
						, &trans_pbs);
				}
				else
				{
					/* RFC 2407 (IPSEC DOI) 4.5 specifies that
					 * the default is "unspecified (host-dependent)".
					 * This makes little sense, so we always specify it.
					 *
					 * Unlike other IPSEC transforms, IPCOMP defaults
					 * to Transport Mode, so we can exploit the default
					 * (draft-shacham-ippcp-rfc2393bis-05.txt 4.1).
					 */
					if (p->protoid != PROTO_IPCOMP
					|| st->st_policy & POLICY_TUNNEL)
					{
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
						if ((st->nat_traversal & NAT_T_DETECTED)
						&& !(st->st_policy & POLICY_TUNNEL))
						{
							/* Inform user that we will not respect policy and only
							 * propose Tunnel Mode
							 */
							loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
								"Transport Mode not allowed due to security concerns -- "
								"using Tunnel mode");
						}
#endif
						out_attr(ENCAPSULATION_MODE
#ifdef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
							, NAT_T_ENCAPSULATION_MODE(st, st->st_policy)
#else
								/* If NAT-T is detected, use UDP_TUNNEL as long as Transport
								 * Mode has security concerns.
								 *
								 * User has been informed of that
								 */
							, NAT_T_ENCAPSULATION_MODE(st, POLICY_TUNNEL)
#endif
							, attr_desc, attr_val_descs
							, &trans_pbs);
					}
					out_attr(SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS
						, attr_desc, attr_val_descs
						, &trans_pbs);
					out_attr(SA_LIFE_DURATION
						, st->st_connection->sa_ipsec_life_seconds
						, attr_desc, attr_val_descs
						, &trans_pbs);
				}

				/* spit out attributes from table */
				for (an = 0; an != t->attr_cnt; an++)
				{
					struct db_attr *a = &t->attrs[an];

					out_attr(a->type, a->val
						, attr_desc, attr_val_descs
						, &trans_pbs);
				}

				close_output_pbs(&trans_pbs);
			}
			close_output_pbs(&proposal_pbs);
		}
		/* end of a conjunction of proposals */
	}
	close_output_pbs(&sa_pbs);
	ret = TRUE;

return_out:

#if !defined NO_KERNEL_ALG || !defined NO_IKE_ALG
	if (db_ctx)
			db_destroy(db_ctx);
#endif
	return ret;
}

/* Handle long form of duration attribute.
 * The code is can only handle values that can fit in unsigned long.
 * "Clamping" is probably an acceptable way to impose this limitation.
 */
static u_int32_t decode_long_duration(pb_stream *pbs)
{
	u_int32_t val = 0;

	/* ignore leading zeros */
	while (pbs_left(pbs) != 0 && *pbs->cur == '\0')
		pbs->cur++;

	if (pbs_left(pbs) > sizeof(val))
	{
		/* "clamp" too large value to max representable value */
		val = UINT32_MAX;
		DBG(DBG_PARSING, DBG_log("   too large duration clamped to: %lu"
			, (unsigned long)val));
	}
	else
	{
		/* decode number */
		while (pbs_left(pbs) != 0)
			val = (val << BITS_PER_BYTE) | *pbs->cur++;
		DBG(DBG_PARSING, DBG_log("   long duration: %lu", (unsigned long)val));
	}
	return val;
}

/* Preparse the body of an ISAKMP SA Payload and
 * return body of ISAKMP Proposal Payload
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 */
notification_t
preparse_isakmp_sa_body(const struct isakmp_sa *sa
					  , pb_stream *sa_pbs
					  , u_int32_t *ipsecdoisit
					  , pb_stream *proposal_pbs
					  , struct isakmp_proposal *proposal)
{
	/* DOI */
	if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
	{
		loglog(RC_LOG_SERIOUS, "Unknown/unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
		/* XXX Could send notification back */
		return ISAKMP_DOI_NOT_SUPPORTED;
	}

	/* Situation */
	if (!in_struct(ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
	{
		return ISAKMP_SITUATION_NOT_SUPPORTED;
	}
	if (*ipsecdoisit != SIT_IDENTITY_ONLY)
	{
		loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
			, bitnamesof(sit_bit_names, *ipsecdoisit));
		/* XXX Could send notification back */
		return ISAKMP_SITUATION_NOT_SUPPORTED;
	}

	/* The rules for ISAKMP SAs are scattered.
	 * RFC 2409 "IKE" section 5 says that there
	 * can only be one SA, and it can have only one proposal in it.
	 * There may well be multiple transforms.
	 */
	if (!in_struct(proposal, &isakmp_proposal_desc, sa_pbs, proposal_pbs))
	{
		return ISAKMP_PAYLOAD_MALFORMED;
	}
	if (proposal->isap_np != ISAKMP_NEXT_NONE)
	{
		loglog(RC_LOG_SERIOUS, "Proposal Payload must be alone in Oakley SA; found %s following Proposal"
			, enum_show(&payload_names, proposal->isap_np));
		return ISAKMP_PAYLOAD_MALFORMED;
	}

	if (proposal->isap_protoid != PROTO_ISAKMP)
	{
		loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) found in Oakley Proposal"
			, enum_show(&protocol_names, proposal->isap_protoid));
		return ISAKMP_INVALID_PROTOCOL_ID;
	}

	/* Just what should we accept for the SPI field?
	 * The RFC is sort of contradictory.  We will ignore the SPI
	 * as long as it is of the proper size.
	 *
	 * From RFC2408 2.4 Identifying Security Associations:
	 *   During phase 1 negotiations, the initiator and responder cookies
	 *   determine the ISAKMP SA. Therefore, the SPI field in the Proposal
	 *   payload is redundant and MAY be set to 0 or it MAY contain the
	 *   transmitting entity's cookie.
	 *
	 * From RFC2408 3.5 Proposal Payload:
	 *    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
	 *       the Protocol-Id.  In the case of ISAKMP, the Initiator and
	 *       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
	 *       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
	 *       sixteen (16).  If the SPI Size is non-zero, the content of the
	 *       SPI field MUST be ignored.  If the SPI Size is not a multiple of
	 *       4 octets it will have some impact on the SPI field and the
	 *       alignment of all payloads in the message.  The Domain of
	 *       Interpretation (DOI) will dictate the SPI Size for other
	 *       protocols.
	 */
	if (proposal->isap_spisize == 0)
	{
		/* empty (0) SPI -- fine */
	}
	else if (proposal->isap_spisize <= MAX_ISAKMP_SPI_SIZE)
	{
		u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

		if (!in_raw(junk_spi, proposal->isap_spisize, proposal_pbs, "Oakley SPI"))
			return ISAKMP_PAYLOAD_MALFORMED;
	}
	else
	{
		loglog(RC_LOG_SERIOUS, "invalid SPI size (%u) in Oakley Proposal"
			, (unsigned)proposal->isap_spisize);
		return ISAKMP_INVALID_SPI;
	}
	return ISAKMP_NOTHING_WRONG;
}

static struct {
	u_int8_t *start;
	u_int8_t *cur;
	u_int8_t *roof;
} backup;

/**
 * Backup the pointer into a pb_stream
 */
void backup_pbs(pb_stream *pbs)
{
	backup.start = pbs->start;
	backup.cur   = pbs->cur;
	backup.roof  = pbs->roof;
}

/**
 * Restore the pointer into a pb_stream
 */
void restore_pbs(pb_stream *pbs)
{
	pbs->start = backup.start;
	pbs->cur   = backup.cur;
	pbs->roof  = backup.roof;
}

/**
 * Parse an ISAKMP Proposal Payload for RSA and PSK authentication policies
 */
notification_t parse_isakmp_policy(pb_stream *proposal_pbs, u_int notrans,
								   lset_t *policy)
{
	int last_transnum = -1;

	*policy = LEMPTY;

	while (notrans--)
	{
		pb_stream trans_pbs;
		u_char *attr_start;
		size_t attr_len;
		struct isakmp_transform trans;

		if (!in_struct(&trans, &isakmp_isakmp_transform_desc, proposal_pbs, &trans_pbs))
		{
			return ISAKMP_BAD_PROPOSAL_SYNTAX;
		}
		if (trans.isat_transnum <= last_transnum)
		{
			/* picky, picky, picky */
			loglog(RC_LOG_SERIOUS, "Transform Numbers are not monotonically increasing"
				" in Oakley Proposal");
			return ISAKMP_BAD_PROPOSAL_SYNTAX;
		}
		last_transnum = trans.isat_transnum;

		if (trans.isat_transid != KEY_IKE)
		{
			loglog(RC_LOG_SERIOUS, "expected KEY_IKE but found %s in Oakley Transform"
				, enum_show(&isakmp_transformid_names, trans.isat_transid));
			return ISAKMP_INVALID_TRANSFORM_ID;
		}

		attr_start = trans_pbs.cur;
		attr_len = pbs_left(&trans_pbs);

		/* preprocess authentication attributes only */
		while (pbs_left(&trans_pbs) != 0)
		{
			struct isakmp_attribute a;
			pb_stream attr_pbs;

			if (!in_struct(&a, &isakmp_oakley_attribute_desc, &trans_pbs, &attr_pbs))
			{
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}
			passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);

			switch (a.isaat_af_type)
			{
			case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
				switch (a.isaat_lv)
				{
				case OAKLEY_PRESHARED_KEY:
					*policy |= POLICY_PSK;
					break;
				case OAKLEY_RSA_SIG:
				case OAKLEY_ECDSA_256:
				case OAKLEY_ECDSA_384:
				case OAKLEY_ECDSA_521:
					*policy |= POLICY_PUBKEY;
					break;
				case XAUTHInitPreShared:
					*policy |= POLICY_XAUTH_SERVER;
					/* fall through */
				case XAUTHRespPreShared:
					*policy |= POLICY_XAUTH_PSK;
					break;
				case XAUTHInitRSA:
					*policy |= POLICY_XAUTH_SERVER;
					/* fall through */
				case XAUTHRespRSA:
					*policy |= POLICY_XAUTH_RSASIG;
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
		}
	}
	DBG(DBG_CONTROL|DBG_PARSING,
		DBG_log("preparse_isakmp_policy: peer requests %s authentication"
				, prettypolicy(*policy))
	)
	return ISAKMP_NOTHING_WRONG;
}

/**
 * Check that we can find a preshared secret
 */
static err_t find_preshared_key(struct state* st)
{
	err_t ugh = NULL;
	connection_t *c = st->st_connection;

	if (get_preshared_secret(c) == NULL)
	{
		char his_id[BUF_LEN];

		if (his_id_was_instantiated(c))
		{
			strcpy(his_id, "%any");
		}
		else
		{
			snprintf(his_id, sizeof(his_id), "%Y", c->spd.that.id);
		}
		ugh = builddiag("Can't authenticate: no preshared key found "
						"for '%Y' and '%s'", c->spd.this.id, his_id);
	}
	return ugh;
}

/* Parse the body of an ISAKMP SA Payload (i.e. Phase 1 / Main Mode).
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted.
 *
 * This routine is used by main_inI1_outR1() and main_inR1_outI2().
 */
notification_t parse_isakmp_sa_body(u_int32_t ipsecdoisit,
									pb_stream *proposal_pbs,
									struct isakmp_proposal *proposal,
									pb_stream *r_sa_pbs,
									struct state *st,
									bool initiator)
{
	connection_t *c = st->st_connection;
	unsigned no_trans_left;

	/* for each transform payload... */
	no_trans_left = proposal->isap_notrans;

	for (;;)
	{
		pb_stream trans_pbs;
		u_char *attr_start;
		size_t attr_len;
		struct isakmp_transform trans;
		lset_t seen_attrs = 0;
		lset_t seen_durations = 0;
		u_int16_t life_type = 0;
		struct oakley_trans_attrs ta = { .encrypter = NULL };
		err_t ugh = NULL;       /* set to diagnostic when problem detected */

		/* initialize only optional field in ta */
		ta.life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;    /* When this SA expires (seconds) */

		if (no_trans_left == 0)
		{
			loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
			return ISAKMP_BAD_PROPOSAL_SYNTAX;
		}

		in_struct(&trans, &isakmp_isakmp_transform_desc, proposal_pbs, &trans_pbs);
		attr_start = trans_pbs.cur;
		attr_len = pbs_left(&trans_pbs);

		/* process all the attributes that make up the transform */

		while (pbs_left(&trans_pbs) != 0)
		{
			struct isakmp_attribute a;
			pb_stream attr_pbs;
			u_int32_t val;      /* room for larger values */

			if (!in_struct(&a, &isakmp_oakley_attribute_desc, &trans_pbs, &attr_pbs))
				return ISAKMP_BAD_PROPOSAL_SYNTAX;

			passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);

			if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
			{
				loglog(RC_LOG_SERIOUS, "repeated %s attribute in Oakley Transform %u"
					, enum_show(&oakley_attr_names, a.isaat_af_type)
					, trans.isat_transnum);
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}

			seen_attrs |= LELEM(a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

			val = a.isaat_lv;

			DBG(DBG_PARSING,
			{
				enum_names *vdesc = oakley_attr_val_descs
					[a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK];

				if (vdesc != NULL)
				{
					const char *nm = enum_name(vdesc, val);

					if (nm != NULL)
						DBG_log("   [%u is %s]", (unsigned)val, nm);
				}
			});

			switch (a.isaat_af_type)
			{
			case OAKLEY_ENCRYPTION_ALGORITHM | ISAKMP_ATTR_AF_TV:
				if (ike_alg_get_crypter(val))
				{
					ta.encrypt = val;
					ta.encrypter = ike_alg_get_crypter(val);
					ta.enckeylen = ta.encrypter->keydeflen;
				}
				else
				{
					ugh = builddiag("%s is not supported"
							, enum_show(&oakley_enc_names, val));
				}
				break;

			case OAKLEY_HASH_ALGORITHM | ISAKMP_ATTR_AF_TV:
				if (ike_alg_get_hasher(val))
				{
					ta.hash = val;
					ta.hasher = ike_alg_get_hasher(val);
				}
				else
				{
					ugh = builddiag("%s is not supported"
							, enum_show(&oakley_hash_names, val));
				}
				break;

			case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
				{
					/* check that authentication method is acceptable */
					lset_t iap = st->st_policy & POLICY_ID_AUTH_MASK;

					/* is the initiator the XAUTH client? */
					bool xauth_init = ( initiator && (st->st_policy & POLICY_XAUTH_SERVER) == LEMPTY)
								   || (!initiator && (st->st_policy & POLICY_XAUTH_SERVER) != LEMPTY);

					switch (val)
					{
					case OAKLEY_PRESHARED_KEY:
						if ((iap & POLICY_PSK) == LEMPTY)
						{
							ugh = "policy does not allow pre-shared key authentication";
						}
						else
						{
							ugh = find_preshared_key(st);
							ta.auth = OAKLEY_PRESHARED_KEY;
						}
						break;
					case XAUTHInitPreShared:
						if ((iap & POLICY_XAUTH_PSK) == LEMPTY || !xauth_init)
						{
							ugh = "policy does not allow XAUTHInitPreShared authentication";
						}
						else
						{
							ugh = find_preshared_key(st);
							ta.auth = XAUTHInitPreShared;
						}
						break;
					case XAUTHRespPreShared:
						if ((iap & POLICY_XAUTH_PSK) == LEMPTY || xauth_init)
						{
							ugh = "policy does not allow XAUTHRespPreShared authentication";
						}
						else
						{
							ugh = find_preshared_key(st);
							ta.auth = XAUTHRespPreShared;
						}
						break;
					case OAKLEY_RSA_SIG:
					case OAKLEY_ECDSA_256:
					case OAKLEY_ECDSA_384:
					case OAKLEY_ECDSA_521:
						if ((iap & POLICY_PUBKEY) == LEMPTY)
						{
							ugh = "policy does not allow public key authentication";
						}
						else
						{
							ta.auth = val;
						}
						break;
					case XAUTHInitRSA:
						if ((iap & POLICY_XAUTH_RSASIG) == LEMPTY || !xauth_init)
						{
							ugh = "policy does not allow XAUTHInitRSA authentication";
						}
						else
						{
							ta.auth = XAUTHInitRSA;
						}
						break;
					case XAUTHRespRSA:
						if ((iap & POLICY_XAUTH_RSASIG) == LEMPTY || xauth_init)
						{
							ugh = "policy does not allow XAUTHRespRSA authentication";
						}
						else
						{
							ta.auth = XAUTHRespRSA;
						}
						break;
					default:
						ugh = builddiag("Pluto does not support %s authentication"
							, enum_show(&oakley_auth_names, val));
						break;
					}
				}
				break;

			case OAKLEY_GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
				ta.group = ike_alg_get_dh_group(val);
				if (ta.group == NULL)
				{
					ugh = builddiag("%s is not supported"
							, enum_show(&oakley_group_names, val));
				}
				break;

			case OAKLEY_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
				switch (val)
				{
				case OAKLEY_LIFE_SECONDS:
				case OAKLEY_LIFE_KILOBYTES:
					if (LHAS(seen_durations, val))
					{
						loglog(RC_LOG_SERIOUS
								, "attribute OAKLEY_LIFE_TYPE value %s repeated"
								, enum_show(&oakley_lifetime_names, val));
						return ISAKMP_BAD_PROPOSAL_SYNTAX;
					}
					seen_durations |= LELEM(val);
					life_type = val;
					break;
				default:
					ugh = builddiag("unknown value %s"
							, enum_show(&oakley_lifetime_names, val));
					break;
				}
				break;

			case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
				val = decode_long_duration(&attr_pbs);
				/* fall through */
			case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
				if (!LHAS(seen_attrs, OAKLEY_LIFE_TYPE))
				{
					ugh = "OAKLEY_LIFE_DURATION attribute not preceded by OAKLEY_LIFE_TYPE attribute";
					break;
				}
				seen_attrs &= ~(LELEM(OAKLEY_LIFE_DURATION) | LELEM(OAKLEY_LIFE_TYPE));

				switch (life_type)
				{
				case OAKLEY_LIFE_SECONDS:
					if (val > OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM)
					{
#ifdef CISCO_QUIRKS
						plog("peer requested %lu seconds"
										" which exceeds our limit %d seconds"
										, (long) val
										, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
						plog("lifetime reduced to %d seconds "
										"(todo: IPSEC_RESPONDER_LIFETIME notification)"
										, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
						val = OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM;
#else
						ugh = builddiag("peer requested %lu seconds"
										" which exceeds our limit %d seconds"
										, (long) val
										, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
#endif
					}
					ta.life_seconds = val;
					break;
				case OAKLEY_LIFE_KILOBYTES:
					ta.life_kilobytes = val;
					break;
				default:
					bad_case(life_type);
				}
				break;

			case OAKLEY_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				if ((seen_attrs & LELEM(OAKLEY_ENCRYPTION_ALGORITHM)) == 0)
				{
					ugh = "OAKLEY_KEY_LENGTH attribute not preceded by "
						  "OAKLEY_ENCRYPTION_ALGORITHM attribute";
					break;
				}
				if (ta.encrypter == NULL)
				{
					ugh = "NULL encrypter with seen OAKLEY_ENCRYPTION_ALGORITHM";
					break;
				}
				/*
				 * check if this keylen is compatible with specified algorithm
				 */
				if (val
				&& (val < ta.encrypter->keyminlen || val > ta.encrypter->keymaxlen))
				{
					ugh = "peer proposed key length not valid for "
						  "encryption algorithm specified";
				}
				ta.enckeylen = val;
				break;
#if 0 /* not yet supported */
			case OAKLEY_GROUP_TYPE | ISAKMP_ATTR_AF_TV:
			case OAKLEY_PRF | ISAKMP_ATTR_AF_TV:
			case OAKLEY_FIELD_SIZE | ISAKMP_ATTR_AF_TV:

			case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TLV:
			case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TV:
			case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TLV:
#endif
			default:
				/* fix compiler warning */
				memset(&ta, 0, sizeof(ta));
				ugh = "unsupported OAKLEY attribute";
				break;
			}

			if (ugh != NULL)
			{
				loglog(RC_LOG_SERIOUS, "%s.  Attribute %s"
					, ugh, enum_show(&oakley_attr_names, a.isaat_af_type));
				break;
			}
		}

		/*
		 * ML: at last check for allowed transforms in alg_info_ike
		 *     (ALG_INFO_F_STRICT flag)
		 */
		if (ugh == NULL)
		{
			if (!ike_alg_ok_final(ta.encrypt, ta.enckeylen, ta.hash,
				ta.group ? ta.group->algo_id : -1, c->alg_info_ike))
			{
				ugh = "OAKLEY proposal refused";
			}
		}

		if (ugh == NULL)
		{
			/* a little more checking is in order */
			{
				lset_t missing
					= ~seen_attrs
					& (LELEM(OAKLEY_ENCRYPTION_ALGORITHM)
					  | LELEM(OAKLEY_HASH_ALGORITHM)
					  | LELEM(OAKLEY_AUTHENTICATION_METHOD)
					  | LELEM(OAKLEY_GROUP_DESCRIPTION));

				if (missing)
				{
					loglog(RC_LOG_SERIOUS, "missing mandatory attribute(s) %s in Oakley Transform %u"
						, bitnamesof(oakley_attr_bit_names, missing)
						, trans.isat_transnum);
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}
			}
			/* We must have liked this transform.
			 * Lets finish early and leave.
			 */

			DBG(DBG_PARSING | DBG_CRYPT
				, DBG_log("Oakley Transform %u accepted", trans.isat_transnum));

			if (r_sa_pbs != NULL)
			{
				struct isakmp_proposal r_proposal = *proposal;
				pb_stream r_proposal_pbs;
				struct isakmp_transform r_trans = trans;
				pb_stream r_trans_pbs;

				/* Situation */
				if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
					impossible();

				/* Proposal */
#ifdef EMIT_ISAKMP_SPI
				r_proposal.isap_spisize = COOKIE_SIZE;
#else
				r_proposal.isap_spisize = 0;
#endif
				r_proposal.isap_notrans = 1;
				if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
					impossible();

				/* SPI */
#ifdef EMIT_ISAKMP_SPI
				if (!out_raw(my_cookie, COOKIE_SIZE, &r_proposal_pbs, "SPI"))
					impossible();
				r_proposal.isap_spisize = COOKIE_SIZE;
#else
				/* none (0) */
#endif

				/* Transform */
				r_trans.isat_np = ISAKMP_NEXT_NONE;
				if (!out_struct(&r_trans, &isakmp_isakmp_transform_desc, &r_proposal_pbs, &r_trans_pbs))
					impossible();

				if (!out_raw(attr_start, attr_len, &r_trans_pbs, "attributes"))
					impossible();
				close_output_pbs(&r_trans_pbs);
				close_output_pbs(&r_proposal_pbs);
				close_output_pbs(r_sa_pbs);
			}

			/* copy over the results */
			st->st_oakley = ta;
			return ISAKMP_NOTHING_WRONG;
		}

		/* on to next transform */
		no_trans_left--;

		if (trans.isat_np == ISAKMP_NEXT_NONE)
		{
			if (no_trans_left != 0)
			{
				loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}
			break;
		}
		if (trans.isat_np != ISAKMP_NEXT_T)
		{
			loglog(RC_LOG_SERIOUS, "unexpected %s payload in Oakley Proposal"
				, enum_show(&payload_names, proposal->isap_np));
			return ISAKMP_BAD_PROPOSAL_SYNTAX;
		}
	}
	loglog(RC_LOG_SERIOUS, "no acceptable Oakley Transform");
	return ISAKMP_NO_PROPOSAL_CHOSEN;
}

/* Parse the body of an IPsec SA Payload (i.e. Phase 2 / Quick Mode).
 *
 * The main routine is parse_ipsec_sa_body; other functions defined
 * between here and there are just helpers.
 *
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted into it.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single transform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * Since all ISAKMP groups in all SA Payloads must match, st->st_pfs_group
 * holds this across multiple payloads.
 * &unset_group signifies not yet "set"; NULL signifies NONE.
 *
 * This routine is used by quick_inI1_outR1() and quick_inR1_outI2().
 */

static const struct ipsec_trans_attrs null_ipsec_trans_attrs = {
	0,                                  /* transid (NULL, for now) */
	0,                                  /* spi */
	SA_LIFE_DURATION_DEFAULT,           /* life_seconds */
	SA_LIFE_DURATION_K_DEFAULT,         /* life_kilobytes */
	ENCAPSULATION_MODE_UNSPECIFIED,     /* encapsulation */
	AUTH_ALGORITHM_NONE,                /* auth */
	0,                                  /* key_len */
	0,                                  /* key_rounds */
};

static bool parse_ipsec_transform(struct isakmp_transform *trans,
								  struct ipsec_trans_attrs *attrs,
								  pb_stream *prop_pbs,
								  pb_stream *trans_pbs,
								  struct_desc *trans_desc,
								  int previous_transnum, /* or -1 if none */
								  bool selection, bool is_last, bool is_ipcomp,
								  struct state *st)  /* current state object */
{
	lset_t seen_attrs = 0;
	lset_t seen_durations = 0;
	u_int16_t life_type = 0;
	const struct dh_desc *pfs_group = NULL;

	if (!in_struct(trans, trans_desc, prop_pbs, trans_pbs))
	{
		return FALSE;
	}
	if (trans->isat_transnum <= previous_transnum)
	{
		loglog(RC_LOG_SERIOUS, "Transform Numbers in Proposal are not monotonically increasing");
		return FALSE;
	}

	switch (trans->isat_np)
	{
		case ISAKMP_NEXT_T:
			if (is_last)
			{
				loglog(RC_LOG_SERIOUS, "Proposal Payload has more Transforms than specified");
				return FALSE;
			}
			break;
		case ISAKMP_NEXT_NONE:
			if (!is_last)
			{
				loglog(RC_LOG_SERIOUS, "Proposal Payload has fewer Transforms than specified");
				return FALSE;
			}
			break;
		default:
			loglog(RC_LOG_SERIOUS, "expecting Transform Payload, but found %s in Proposal"
				, enum_show(&payload_names, trans->isat_np));
			return FALSE;
	}

	*attrs = null_ipsec_trans_attrs;
	attrs->transid = trans->isat_transid;

	while (pbs_left(trans_pbs) != 0)
	{
		struct isakmp_attribute a;
		pb_stream attr_pbs;
		enum_names *vdesc;
		u_int32_t val;  /* room for larger value */
		bool ipcomp_inappropriate = is_ipcomp;  /* will get reset if OK */

		if (!in_struct(&a, &isakmp_ipsec_attribute_desc, trans_pbs, &attr_pbs))
			return FALSE;

		passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);

		if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
		{
			loglog(RC_LOG_SERIOUS, "repeated %s attribute in IPsec Transform %u"
				, enum_show(&ipsec_attr_names, a.isaat_af_type)
				, trans->isat_transnum);
			return FALSE;
		}

		seen_attrs |= LELEM(a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);

		val = a.isaat_lv;

		vdesc  = ipsec_attr_val_descs[a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK];
		if (vdesc != NULL)
		{
			if (enum_name(vdesc, val) == NULL)
			{
				loglog(RC_LOG_SERIOUS, "invalid value %u for attribute %s in IPsec Transform"
					, (unsigned)val, enum_show(&ipsec_attr_names, a.isaat_af_type));
				return FALSE;
			}
			DBG(DBG_PARSING
				, if ((a.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV)
					DBG_log("   [%u is %s]"
						, (unsigned)val, enum_show(vdesc, val)));
		}

		switch (a.isaat_af_type)
		{
			case SA_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
				ipcomp_inappropriate = FALSE;
				if (LHAS(seen_durations, val))
				{
					loglog(RC_LOG_SERIOUS, "attribute SA_LIFE_TYPE value %s repeated in message"
						, enum_show(&sa_lifetime_names, val));
					return FALSE;
				}
				seen_durations |= LELEM(val);
				life_type = val;
				break;
			case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
				val = decode_long_duration(&attr_pbs);
				/* fall through */
			case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
				ipcomp_inappropriate = FALSE;
				if (!LHAS(seen_attrs, SA_LIFE_DURATION))
				{
					loglog(RC_LOG_SERIOUS, "SA_LIFE_DURATION IPsec attribute not preceded by SA_LIFE_TYPE attribute");
					return FALSE;
				}
				seen_attrs &= ~(LELEM(SA_LIFE_DURATION) | LELEM(SA_LIFE_TYPE));

				switch (life_type)
				{
					case SA_LIFE_TYPE_SECONDS:
						/* silently limit duration to our maximum */
						attrs->life_seconds = val <= SA_LIFE_DURATION_MAXIMUM
							? val : SA_LIFE_DURATION_MAXIMUM;
						break;
					case SA_LIFE_TYPE_KBYTES:
						attrs->life_kilobytes = val;
						break;
					default:
						bad_case(life_type);
				}
				break;
			case GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
				if (is_ipcomp)
				{
					/* Accept reluctantly.  Should not happen, according to
					 * draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
					 */
					ipcomp_inappropriate = FALSE;
					loglog(RC_COMMENT
						, "IPCA (IPcomp SA) contains GROUP_DESCRIPTION."
						"  Ignoring inapproprate attribute.");
				}
				pfs_group = ike_alg_get_dh_group(val);
				if (pfs_group == NULL)
				{
					loglog(RC_LOG_SERIOUS, "only OAKLEY_GROUP_MODP1024 and OAKLEY_GROUP_MODP1536 supported for PFS");
					return FALSE;
				}
				break;
			case ENCAPSULATION_MODE | ISAKMP_ATTR_AF_TV:
				ipcomp_inappropriate = FALSE;
				switch (val)
				{
				case ENCAPSULATION_MODE_TUNNEL:
				case ENCAPSULATION_MODE_TRANSPORT:
					if (st->nat_traversal & NAT_T_DETECTED)
					{
						loglog(RC_LOG_SERIOUS
							, "%s must only be used if NAT-Traversal is not detected"
							, enum_name(&enc_mode_names, val));
						/*
						 * Accept it anyway because SSH-Sentinel does not
						 * use UDP_TUNNEL or UDP_TRANSPORT for the diagnostic.
						 *
						 * remove when SSH-Sentinel is fixed
						 */
#ifdef I_DONT_CARE_OF_SSH_SENTINEL
						return FALSE;
#endif
					}
					attrs->encapsulation = val;
					break;
				case ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
					loglog(RC_LOG_SERIOUS
						, "NAT-Traversal: Transport mode disabled due to security concerns");
					return FALSE;
#endif
				case ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS:
					if (st->nat_traversal & NAT_T_WITH_RFC_VALUES)
					{
						loglog(RC_LOG_SERIOUS
							, "%s must only be used with old IETF drafts"
							, enum_name(&enc_mode_names, val));
						return FALSE;
					}
					else if (st->nat_traversal & NAT_T_DETECTED)
					{
						attrs->encapsulation = val
								- ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS
								+ ENCAPSULATION_MODE_TUNNEL;
					}
					else
					{
						loglog(RC_LOG_SERIOUS
							, "%s must only be used if NAT-Traversal is detected"
							, enum_name(&enc_mode_names, val));
						return FALSE;
					}
					break;
					case ENCAPSULATION_MODE_UDP_TRANSPORT_RFC:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
						loglog(RC_LOG_SERIOUS
							, "NAT-Traversal: Transport mode disabled due "
							  "to security concerns");
						return FALSE;
#endif
					case ENCAPSULATION_MODE_UDP_TUNNEL_RFC:
						if ((st->nat_traversal & NAT_T_DETECTED)
						&& (st->nat_traversal & NAT_T_WITH_RFC_VALUES))
						{
							attrs->encapsulation = val
										- ENCAPSULATION_MODE_UDP_TUNNEL_RFC
										+ ENCAPSULATION_MODE_TUNNEL;
						}
						else if (st->nat_traversal & NAT_T_DETECTED)
						{
							loglog(RC_LOG_SERIOUS
								, "%s must only be used with NAT-T RFC"
								, enum_name(&enc_mode_names, val));
							return FALSE;
						}
						else
						{
							loglog(RC_LOG_SERIOUS
								, "%s must only be used if NAT-Traversal is detected"
								, enum_name(&enc_mode_names, val));
							return FALSE;
						}
						break;
					default:
						loglog(RC_LOG_SERIOUS
							, "unknown ENCAPSULATION_MODE %d in IPSec SA", val);
						return FALSE;
				}
				break;
			case AUTH_ALGORITHM | ISAKMP_ATTR_AF_TV:
				attrs->auth = val;
				break;
			case KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				attrs->key_len = val;
				break;
			case KEY_ROUNDS | ISAKMP_ATTR_AF_TV:
				attrs->key_rounds = val;
				break;
#if 0 /* not yet implemented */
			case COMPRESS_DICT_SIZE | ISAKMP_ATTR_AF_TV:
				break;
			case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TV:
				break;

			case SA_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
				break;
			case COMPRESS_PRIVATE_ALG | ISAKMP_ATTR_AF_TLV:
				break;
#endif
			default:
				loglog(RC_LOG_SERIOUS, "unsupported IPsec attribute %s"
					, enum_show(&ipsec_attr_names, a.isaat_af_type));
				return FALSE;
		}
		if (ipcomp_inappropriate)
		{
			loglog(RC_LOG_SERIOUS, "IPsec attribute %s inappropriate for IPCOMP"
				, enum_show(&ipsec_attr_names, a.isaat_af_type));
			return FALSE;
		}
	}

	/* Although an IPCOMP SA (IPCA) ought not to have a pfs_group,
	 * if it does, demand that it be consistent.
	 * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
	 */
	if (!is_ipcomp || pfs_group != NULL)
	{
		if (st->st_pfs_group == &unset_group)
			st->st_pfs_group = pfs_group;

		if (st->st_pfs_group != pfs_group)
		{
			loglog(RC_LOG_SERIOUS, "GROUP_DESCRIPTION inconsistent with that of %s in IPsec SA"
				, selection? "the Proposal" : "a previous Transform");
			return FALSE;
		}
	}

	if (LHAS(seen_attrs, SA_LIFE_DURATION))
	{
		loglog(RC_LOG_SERIOUS, "SA_LIFE_TYPE IPsec attribute not followed by SA_LIFE_DURATION attribute in message");
		return FALSE;
	}

	if (!LHAS(seen_attrs, ENCAPSULATION_MODE))
	{
		if (is_ipcomp)
		{
			/* draft-shacham-ippcp-rfc2393bis-05.txt 4.1:
			 * "If the Encapsulation Mode is unspecified,
			 * the default value of Transport Mode is assumed."
			 * This contradicts/overrides the DOI (quuoted below).
			 */
			attrs->encapsulation = ENCAPSULATION_MODE_TRANSPORT;
		}
		else
		{
			/* ??? Technically, RFC 2407 (IPSEC DOI) 4.5 specifies that
			 * the default is "unspecified (host-dependent)".
			 * This makes little sense, so we demand that it be specified.
			 */
			loglog(RC_LOG_SERIOUS, "IPsec Transform must specify ENCAPSULATION_MODE");
			return FALSE;
		}
	}

	/* ??? should check for key_len and/or key_rounds if required */

	return TRUE;
}

static void
echo_proposal(
	struct isakmp_proposal r_proposal,  /* proposal to emit */
	struct isakmp_transform r_trans,    /* winning transformation within it */
	u_int8_t np,                        /* Next Payload for proposal */
	pb_stream *r_sa_pbs,                /* SA PBS into which to emit */
	struct ipsec_proto_info *pi,        /* info about this protocol instance */
	struct_desc *trans_desc,            /* descriptor for this transformation */
	pb_stream *trans_pbs,               /* PBS for incoming transform */
	struct spd_route *sr,               /* host details for the association */
	bool tunnel_mode)                   /* true for inner most tunnel SA */
{
	pb_stream r_proposal_pbs;
	pb_stream r_trans_pbs;

	/* Proposal */
	r_proposal.isap_np = np;
	r_proposal.isap_notrans = 1;
	if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
		impossible();

	/* allocate and emit our CPI/SPI */
	if (r_proposal.isap_protoid == PROTO_IPCOMP)
	{
		/* CPI is stored in network low order end of an
		 * ipsec_spi_t.  So we start a couple of bytes in.
		 * Note: we may fail to generate a satisfactory CPI,
		 * but we'll ignore that.
		 */
		pi->our_spi = get_my_cpi(sr, tunnel_mode);
		out_raw((u_char *) &pi->our_spi
			 + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
			, IPCOMP_CPI_SIZE
			, &r_proposal_pbs, "CPI");
	}
	else
	{
		pi->our_spi = get_ipsec_spi(pi->attrs.spi
			, r_proposal.isap_protoid == PROTO_IPSEC_AH ?
				IPPROTO_AH : IPPROTO_ESP
			, sr
			, tunnel_mode);
		/* XXX should check for errors */
		out_raw((u_char *) &pi->our_spi, IPSEC_DOI_SPI_SIZE
			, &r_proposal_pbs, "SPI");
	}

	/* Transform */
	r_trans.isat_np = ISAKMP_NEXT_NONE;
	if (!out_struct(&r_trans, trans_desc, &r_proposal_pbs, &r_trans_pbs))
		impossible();

	/* Transform Attributes: pure echo */
	trans_pbs->cur = trans_pbs->start + sizeof(struct isakmp_transform);
	if (!out_raw(trans_pbs->cur, pbs_left(trans_pbs)
	, &r_trans_pbs, "attributes"))
		impossible();

	close_output_pbs(&r_trans_pbs);
	close_output_pbs(&r_proposal_pbs);
}

notification_t
parse_ipsec_sa_body(
	pb_stream *sa_pbs,          /* body of input SA Payload */
	const struct isakmp_sa *sa, /* header of input SA Payload */
	pb_stream *r_sa_pbs,        /* if non-NULL, where to emit body of winning SA */
	bool selection,             /* if this SA is a selection, only one transform may appear */
	struct state *st)           /* current state object */
{
	const connection_t *c = st->st_connection;
	u_int32_t ipsecdoisit;
	pb_stream next_proposal_pbs;

	struct isakmp_proposal next_proposal;
	ipsec_spi_t next_spi;

	bool next_full = TRUE;

	/* DOI */
	if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
	{
		loglog(RC_LOG_SERIOUS, "Unknown or unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
		/* XXX Could send notification back */
		return ISAKMP_DOI_NOT_SUPPORTED;
	}

	/* Situation */
	if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
		return ISAKMP_SITUATION_NOT_SUPPORTED;

	if (ipsecdoisit != SIT_IDENTITY_ONLY)
	{
		loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
			, bitnamesof(sit_bit_names, ipsecdoisit));
		/* XXX Could send notification back */
		return ISAKMP_SITUATION_NOT_SUPPORTED;
	}

	/* The rules for IPsec SAs are scattered.
	 * RFC 2408 "ISAKMP" section 4.2 gives some info.
	 * There may be multiple proposals.  Those with identical proposal
	 * numbers must be considered as conjuncts.  Those with different
	 * numbers are disjuncts.
	 * Each proposal may have several transforms, each considered
	 * an alternative.
	 * Each transform may have several attributes, all applying.
	 *
	 * To handle the way proposals are combined, we need to do a
	 * look-ahead.
	 */

	if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
		return ISAKMP_BAD_PROPOSAL_SYNTAX;

	/* for each conjunction of proposals... */
	while (next_full)
	{
		int propno = next_proposal.isap_proposal;
		pb_stream ah_prop_pbs, esp_prop_pbs, ipcomp_prop_pbs;
		struct isakmp_proposal ah_proposal = {0, 0, 0, 0, 0, 0, 0};
		struct isakmp_proposal esp_proposal = {0, 0, 0, 0, 0, 0, 0};
		struct isakmp_proposal ipcomp_proposal = {0, 0, 0, 0, 0, 0, 0};
		ipsec_spi_t ah_spi = 0;
		ipsec_spi_t esp_spi = 0;
		ipsec_spi_t ipcomp_cpi = 0;
		bool ah_seen = FALSE;
		bool esp_seen = FALSE;
		bool ipcomp_seen = FALSE;
		bool tunnel_mode = FALSE;
		int inner_proto = 0;
		u_int16_t well_known_cpi = 0;

		pb_stream ah_trans_pbs, esp_trans_pbs, ipcomp_trans_pbs;
		struct isakmp_transform ah_trans, esp_trans, ipcomp_trans;
		struct ipsec_trans_attrs ah_attrs, esp_attrs, ipcomp_attrs;

		/* for each proposal in the conjunction */
		do {

			if (next_proposal.isap_protoid == PROTO_IPCOMP)
			{
				/* IPCOMP CPI */
				if (next_proposal.isap_spisize == IPSEC_DOI_SPI_SIZE)
				{
					/* This code is to accommodate those peculiar
					 * implementations that send a CPI in the bottom of an
					 * SPI-sized field.
					 * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1
					 */
					u_int8_t filler[IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE];

					if (!in_raw(filler, sizeof(filler)
					 , &next_proposal_pbs, "CPI filler")
					|| !all_zero(filler, sizeof(filler)))
						return ISAKMP_INVALID_SPI;
				}
				else if (next_proposal.isap_spisize != IPCOMP_CPI_SIZE)
				{
					loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper CPI size (%u)"
						, next_proposal.isap_spisize);
					return ISAKMP_INVALID_SPI;
				}

				/* We store CPI in the low order of a network order
				 * ipsec_spi_t.  So we start a couple of bytes in.
				 */
				zero(&next_spi);
				if (!in_raw((u_char *)&next_spi
				  + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
				, IPCOMP_CPI_SIZE, &next_proposal_pbs, "CPI"))
					return ISAKMP_INVALID_SPI;

				/* If sanity ruled, CPIs would have to be such that
				 * the SAID (the triple (CPI, IPCOM, destination IP))
				 * would be unique, just like for SPIs.  But there is a
				 * perversion where CPIs can be well-known and consequently
				 * the triple is not unique.  We hide this fact from
				 * ourselves by fudging the top 16 bits to make
				 * the property true internally!
				 */
				switch (ntohl(next_spi))
				{
				case IPCOMP_DEFLATE:
					well_known_cpi = ntohl(next_spi);
					next_spi = uniquify_his_cpi(next_spi, st);
					if (next_spi == 0)
					{
						loglog(RC_LOG_SERIOUS
							, "IPsec Proposal contains well-known CPI that I cannot uniquify");
						return ISAKMP_INVALID_SPI;
					}
					break;
				default:
					if (ntohl(next_spi) < IPCOMP_FIRST_NEGOTIATED
					|| ntohl(next_spi) > IPCOMP_LAST_NEGOTIATED)
					{
						loglog(RC_LOG_SERIOUS, "IPsec Proposal contains CPI from non-negotiated range (0x%lx)"
							, (unsigned long) ntohl(next_spi));
						return ISAKMP_INVALID_SPI;
					}
					break;
				}
			}
			else
			{
				/* AH or ESP SPI */
				if (next_proposal.isap_spisize != IPSEC_DOI_SPI_SIZE)
				{
					loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper SPI size (%u)"
						, next_proposal.isap_spisize);
					return ISAKMP_INVALID_SPI;
				}

				if (!in_raw((u_char *)&next_spi, sizeof(next_spi), &next_proposal_pbs, "SPI"))
					return ISAKMP_INVALID_SPI;

				/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
				 * RFC 2402 (ESP) 2.4, RFC 2406 (AH) 2.1
				 * IPCOMP???
				 */
				if (ntohl(next_spi) < IPSEC_DOI_SPI_MIN)
				{
					loglog(RC_LOG_SERIOUS, "IPsec Proposal contains invalid SPI (0x%lx)"
						, (unsigned long) ntohl(next_spi));
					return ISAKMP_INVALID_SPI;
				}
			}

			if (next_proposal.isap_notrans == 0)
			{
				loglog(RC_LOG_SERIOUS, "IPsec Proposal contains no Transforms");
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}

			switch (next_proposal.isap_protoid)
			{
			case PROTO_IPSEC_AH:
				if (ah_seen)
				{
					loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous AH Proposals");
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}
				ah_seen = TRUE;
				ah_prop_pbs = next_proposal_pbs;
				ah_proposal = next_proposal;
				ah_spi = next_spi;
				break;

			case PROTO_IPSEC_ESP:
				if (esp_seen)
				{
					loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous ESP Proposals");
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}
				esp_seen = TRUE;
				esp_prop_pbs = next_proposal_pbs;
				esp_proposal = next_proposal;
				esp_spi = next_spi;
				break;

			case PROTO_IPCOMP:
				if (ipcomp_seen)
				{
					loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous IPCOMP Proposals");
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}
				ipcomp_seen = TRUE;
				ipcomp_prop_pbs = next_proposal_pbs;
				ipcomp_proposal = next_proposal;
				ipcomp_cpi = next_spi;
				break;

			default:
				loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) in IPsec Proposal"
					, enum_show(&protocol_names, next_proposal.isap_protoid));
				return ISAKMP_INVALID_PROTOCOL_ID;
			}

			/* refill next_proposal */
			if (next_proposal.isap_np == ISAKMP_NEXT_NONE)
			{
				next_full = FALSE;
				break;
			}
			else if (next_proposal.isap_np != ISAKMP_NEXT_P)
			{
				loglog(RC_LOG_SERIOUS, "unexpected in Proposal: %s"
					, enum_show(&payload_names, next_proposal.isap_np));
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}

			if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
		} while (next_proposal.isap_proposal == propno);

		/* Now that we have all conjuncts, we should try
		 * the Cartesian product of eachs tranforms!
		 * At the moment, we take short-cuts on account of
		 * our rudimentary hard-wired policy.
		 * For now, we find an acceptable AH (if any)
		 * and then an acceptable ESP.  The only interaction
		 * is that the ESP acceptance can know whether there
		 * was an acceptable AH and hence not require an AUTH.
		 */

		if (ah_seen)
		{
			int previous_transnum = -1;
			int tn;

			for (tn = 0; tn != ah_proposal.isap_notrans; tn++)
			{
				int ok_transid = 0;
				bool ok_auth = FALSE;

				if (!parse_ipsec_transform(&ah_trans
				, &ah_attrs
				, &ah_prop_pbs
				, &ah_trans_pbs
				, &isakmp_ah_transform_desc
				, previous_transnum
				, selection
				, tn == ah_proposal.isap_notrans - 1
				, FALSE
				, st))
					return ISAKMP_BAD_PROPOSAL_SYNTAX;

				previous_transnum = ah_trans.isat_transnum;

				/* we must understand ah_attrs.transid
				 * COMBINED with ah_attrs.auth.
				 * See RFC 2407 "IPsec DOI" section 4.4.3
				 * The following combinations are legal,
				 * but we don't implement all of them:
				 * It seems as if each auth algorithm
				 * only applies to one ah transid.
				 * AH_MD5, AUTH_ALGORITHM_HMAC_MD5
				 * AH_MD5, AUTH_ALGORITHM_KPDK (unimplemented)
				 * AH_SHA, AUTH_ALGORITHM_HMAC_SHA1
				 * AH_DES, AUTH_ALGORITHM_DES_MAC (unimplemented)
				 */
				switch (ah_attrs.auth)
				{
					case AUTH_ALGORITHM_NONE:
						loglog(RC_LOG_SERIOUS, "AUTH_ALGORITHM attribute missing in AH Transform");
						return ISAKMP_BAD_PROPOSAL_SYNTAX;

					case AUTH_ALGORITHM_HMAC_MD5:
						ok_auth = TRUE;
						/* fall through */
					case AUTH_ALGORITHM_KPDK:
						ok_transid = AH_MD5;
						break;

					case AUTH_ALGORITHM_HMAC_SHA1:
						ok_auth = TRUE;
						ok_transid = AH_SHA;
						break;

					case AUTH_ALGORITHM_DES_MAC:
						ok_transid = AH_DES;
						break;
				}
				if (ah_attrs.transid != ok_transid)
				{
					loglog(RC_LOG_SERIOUS, "%s attribute inappropriate in %s Transform"
						, enum_name(&auth_alg_names, ah_attrs.auth)
						, enum_show(&ah_transform_names, ah_attrs.transid));
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}
				if (!ok_auth)
				{
					DBG(DBG_CONTROL | DBG_CRYPT
						, DBG_log("%s attribute unsupported"
							" in %s Transform from %s"
							, enum_name(&auth_alg_names, ah_attrs.auth)
							, enum_show(&ah_transform_names, ah_attrs.transid)
							, ip_str(&c->spd.that.host_addr)));
					continue;   /* try another */
				}
				break;  /* we seem to be happy */
			}
			if (tn == ah_proposal.isap_notrans)
				continue;       /* we didn't find a nice one */
			ah_attrs.spi = ah_spi;
			inner_proto = IPPROTO_AH;
			if (ah_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		}

		if (esp_seen)
		{
			int previous_transnum = -1;
			int tn;

			for (tn = 0; tn != esp_proposal.isap_notrans; tn++)
			{
				if (!parse_ipsec_transform(&esp_trans
				, &esp_attrs
				, &esp_prop_pbs
				, &esp_trans_pbs
				, &isakmp_esp_transform_desc
				, previous_transnum
				, selection
				, tn == esp_proposal.isap_notrans - 1
				, FALSE
				, st))
					return ISAKMP_BAD_PROPOSAL_SYNTAX;

				previous_transnum = esp_trans.isat_transnum;

				/* set default key length for AES encryption */
				if (!esp_attrs.key_len && esp_attrs.transid == ESP_AES)
				{
					esp_attrs.key_len = 128; /* bits */
				}

				if (!kernel_alg_esp_enc_ok(esp_attrs.transid, esp_attrs.key_len
					,c->alg_info_esp))
				{
					switch (esp_attrs.transid)
					{
					case ESP_3DES:
						break;
#ifdef SUPPORT_ESP_NULL /* should be about as secure as AH-only */
					case ESP_NULL:
						if (esp_attrs.auth == AUTH_ALGORITHM_NONE)
						{
							loglog(RC_LOG_SERIOUS, "ESP_NULL requires auth algorithm");
							return BAD_PROPOSAL_SYNTAX;
						}
						if (st->st_policy & POLICY_ENCRYPT)
						{
							DBG(DBG_CONTROL | DBG_CRYPT
									, DBG_log("ESP_NULL Transform Proposal from %s"
										" does not satisfy POLICY_ENCRYPT"
										, ip_str(&c->spd.that.host_addr)));
							continue;   /* try another */
						}
						break;
#endif
					default:
						DBG(DBG_CONTROL | DBG_CRYPT
							, DBG_log("unsupported ESP Transform %s from %s"
								, enum_show(&esp_transform_names, esp_attrs.transid)
								, ip_str(&c->spd.that.host_addr)));
						continue;   /* try another */
					}
				}

				if (!kernel_alg_esp_auth_ok(esp_attrs.auth, c->alg_info_esp))
				{
					switch (esp_attrs.auth)
					{
					case AUTH_ALGORITHM_NONE:
						if (!ah_seen)
						{
							DBG(DBG_CONTROL | DBG_CRYPT
								, DBG_log("ESP from %s must either have AUTH or be combined with AH"
									, ip_str(&c->spd.that.host_addr)));
							continue;   /* try another */
						}
						break;
					case AUTH_ALGORITHM_HMAC_MD5:
					case AUTH_ALGORITHM_HMAC_SHA1:
						break;
					default:
						DBG(DBG_CONTROL | DBG_CRYPT
							, DBG_log("unsupported ESP auth alg %s from %s"
								, enum_show(&auth_alg_names, esp_attrs.auth)
								, ip_str(&c->spd.that.host_addr)));
						continue;   /* try another */
					}
				}

				/* A last check for allowed transforms in alg_info_esp
				 * (ALG_INFO_F_STRICT flag)
				 */
				if (!kernel_alg_esp_ok_final(esp_attrs.transid, esp_attrs.key_len
					,esp_attrs.auth, c->alg_info_esp))
				{
					continue;
				}

				if (ah_seen && ah_attrs.encapsulation != esp_attrs.encapsulation)
				{
					/* ??? This should be an error, but is it? */
					DBG(DBG_CONTROL | DBG_CRYPT
						, DBG_log("AH and ESP transforms disagree about encapsulation; TUNNEL presumed"));
				}

				break;  /* we seem to be happy */
			}
			if (tn == esp_proposal.isap_notrans)
				continue;       /* we didn't find a nice one */

			esp_attrs.spi = esp_spi;
			inner_proto = IPPROTO_ESP;
			if (esp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		}
		else if (st->st_policy & POLICY_ENCRYPT)
		{
			DBG(DBG_CONTROL | DBG_CRYPT
				, DBG_log("policy for \"%s\" requires encryption but ESP not in Proposal from %s"
					, c->name, ip_str(&c->spd.that.host_addr)));
			continue;   /* we needed encryption, but didn't find ESP */
		}
		else if ((st->st_policy & POLICY_AUTHENTICATE) && !ah_seen)
		{
			DBG(DBG_CONTROL | DBG_CRYPT
				, DBG_log("policy for \"%s\" requires authentication"
					" but none in Proposal from %s"
					, c->name, ip_str(&c->spd.that.host_addr)));
			continue;   /* we need authentication, but we found neither ESP nor AH */
		}

		if (ipcomp_seen)
		{
			int previous_transnum = -1;
			int tn;

#ifdef NEVER    /* we think IPcomp is working now */
			/**** FUDGE TO PREVENT UNREQUESTED IPCOMP:
			 **** NEEDED BECAUSE OUR IPCOMP IS EXPERIMENTAL (UNSTABLE).
			 ****/
			if (!(st->st_policy & POLICY_COMPRESS))
			{
				plog("compression proposed by %s, but policy for \"%s\" forbids it"
					, ip_str(&c->spd.that.host_addr), c->name);
				continue;       /* unwanted compression proposal */
			}
#endif
			if (!can_do_IPcomp)
			{
				plog("compression proposed by %s, but kernel does not support IPCOMP"
					, ip_str(&c->spd.that.host_addr));
				continue;
			}

			if (well_known_cpi != 0 && !ah_seen && !esp_seen)
			{
				plog("illegal proposal: bare IPCOMP used with well-known CPI");
				return ISAKMP_BAD_PROPOSAL_SYNTAX;
			}

			for (tn = 0; tn != ipcomp_proposal.isap_notrans; tn++)
			{
				if (!parse_ipsec_transform(&ipcomp_trans
				, &ipcomp_attrs
				, &ipcomp_prop_pbs
				, &ipcomp_trans_pbs
				, &isakmp_ipcomp_transform_desc
				, previous_transnum
				, selection
				, tn == ipcomp_proposal.isap_notrans - 1
				, TRUE
				, st))
					return ISAKMP_BAD_PROPOSAL_SYNTAX;

				previous_transnum = ipcomp_trans.isat_transnum;

				if (well_known_cpi != 0 && ipcomp_attrs.transid != well_known_cpi)
				{
					plog("illegal proposal: IPCOMP well-known CPI disagrees with transform");
					return ISAKMP_BAD_PROPOSAL_SYNTAX;
				}

				switch (ipcomp_attrs.transid)
				{
					case IPCOMP_DEFLATE:    /* all we can handle! */
						break;

					default:
						DBG(DBG_CONTROL | DBG_CRYPT
							, DBG_log("unsupported IPCOMP Transform %s from %s"
								, enum_show(&ipcomp_transformid_names, ipcomp_attrs.transid)
								, ip_str(&c->spd.that.host_addr)));
						continue;   /* try another */
				}

				if (ah_seen && ah_attrs.encapsulation != ipcomp_attrs.encapsulation)
				{
					/* ??? This should be an error, but is it? */
					DBG(DBG_CONTROL | DBG_CRYPT
						, DBG_log("AH and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
				} else if (esp_seen && esp_attrs.encapsulation != ipcomp_attrs.encapsulation)
				{
					/* ??? This should be an error, but is it? */
					DBG(DBG_CONTROL | DBG_CRYPT
						, DBG_log("ESP and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
				}

				break;  /* we seem to be happy */
			}
			if (tn == ipcomp_proposal.isap_notrans)
				continue;       /* we didn't find a nice one */
			ipcomp_attrs.spi = ipcomp_cpi;
			inner_proto = IPPROTO_COMP;
			if (ipcomp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				tunnel_mode = TRUE;
		}

		/* Eureka: we liked what we saw -- accept it. */

		if (r_sa_pbs != NULL)
		{
			/* emit what we've accepted */

			/* Situation */
			if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
				impossible();

			/* AH proposal */
			if (ah_seen)
				echo_proposal(ah_proposal
					, ah_trans
					, esp_seen || ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
					, r_sa_pbs
					, &st->st_ah
					, &isakmp_ah_transform_desc
					, &ah_trans_pbs
					, &st->st_connection->spd
					, tunnel_mode && inner_proto == IPPROTO_AH);

			/* ESP proposal */
			if (esp_seen)
				echo_proposal(esp_proposal
					, esp_trans
					, ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
					, r_sa_pbs
					, &st->st_esp
					, &isakmp_esp_transform_desc
					, &esp_trans_pbs
					, &st->st_connection->spd
					, tunnel_mode && inner_proto == IPPROTO_ESP);

			/* IPCOMP proposal */
			if (ipcomp_seen)
				echo_proposal(ipcomp_proposal
					, ipcomp_trans
					, ISAKMP_NEXT_NONE
					, r_sa_pbs
					, &st->st_ipcomp
					, &isakmp_ipcomp_transform_desc
					, &ipcomp_trans_pbs
					, &st->st_connection->spd
					, tunnel_mode && inner_proto == IPPROTO_COMP);

			close_output_pbs(r_sa_pbs);
		}

		/* save decoded version of winning SA in state */

		st->st_ah.present = ah_seen;
		if (ah_seen)
			st->st_ah.attrs = ah_attrs;

		st->st_esp.present = esp_seen;
		if (esp_seen)
			st->st_esp.attrs = esp_attrs;

		st->st_ipcomp.present = ipcomp_seen;
		if (ipcomp_seen)
			st->st_ipcomp.attrs = ipcomp_attrs;

		return ISAKMP_NOTHING_WRONG;
	}

	loglog(RC_LOG_SERIOUS, "no acceptable Proposal in IPsec SA");
	return ISAKMP_NO_PROPOSAL_CHOSEN;
}
