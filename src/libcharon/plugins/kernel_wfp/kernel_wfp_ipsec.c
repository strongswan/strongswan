/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

/* Windows 7, for some fwpmu.h functionality */
#define _WIN32_WINNT 0x0601

#include "kernel_wfp_compat.h"
#include "kernel_wfp_ipsec.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>


typedef struct private_kernel_wfp_ipsec_t private_kernel_wfp_ipsec_t;

struct private_kernel_wfp_ipsec_t {

	/**
	 * Public interface
	 */
	kernel_wfp_ipsec_t public;

	/**
	 * Next SPI to allocate
	 */
	refcount_t nextspi;

	/**
	 * SAD/SPD entries, as reqid => entry_t
	 */
	hashtable_t *entries;

	/**
	 * SAD entry lookup, as sa_entry_t => entry_t
	 */
	hashtable_t *sas;

	/**
	 * Mutex for accessing entries
	 */
	mutex_t *mutex;

	/**
	 * WFP session handle
	 */
	HANDLE handle;
};

/**
 * Security association entry
 */
typedef struct {
	/** SPI for this SA */
	u_int32_t spi;
	/** destination host address for this SPI */
	host_t *dst;
	/** inbound or outbound SA? */
	bool inbound;
	struct {
		/** algorithm */
		u_int16_t alg;
		/** key */
		chunk_t key;
	} integ, encr;
} sa_entry_t;

/**
 * Destroy an SA entry
 */
static void sa_entry_destroy(sa_entry_t *sa)
{
	chunk_clear(&sa->integ.key);
	chunk_clear(&sa->encr.key);
	free(sa);
}

/**
 * Hash function for sas lookup table
 */
static u_int hash_sa(sa_entry_t *key)
{
	return chunk_hash_inc(chunk_from_thing(key->spi),
						  chunk_hash(key->dst->get_address(key->dst)));
}

/**
 * equals function for sas lookup table
 */
static bool equals_sa(sa_entry_t *a, sa_entry_t *b)
{
	return a->spi == b->spi && a->dst->ip_equals(a->dst, b->dst);
}

/**
 * Security policy entry
 */
typedef struct {
	/** policy source addresses */
	traffic_selector_t *src;
	/** policy destinaiton addresses */
	traffic_selector_t *dst;
	/** direction of policy, in|out */
	policy_dir_t direction;
} sp_entry_t;

/**
 * Destroy an SP entry
 */
static void sp_entry_destroy(sp_entry_t *sp)
{
	sp->src->destroy(sp->src);
	sp->dst->destroy(sp->dst);
	free(sp);
}

/**
 * Collection of SA/SP database entries for a reqid
 */
typedef struct {
	/** reqid of entry */
	u_int32_t reqid;
	/** outer address on local host */
	host_t *local;
	/** outer address on remote host */
	host_t *remote;
	/** associated security associations, as sa_entry_t* */
	array_t *sas;
	/** associated policies, as sp_entry_t* */
	array_t *sps;
	/** IPsec protocol, ESP|AH */
	u_int8_t protocol;
	/** IPsec mode, tunnel|transport */
	ipsec_mode_t mode;
	/** UDP encapsulation */
	bool encap;
	/** WFP allocated LUID for inbound filter/tunnel policy ID */
	u_int64_t policy_in;
	/** WFP allocated LUID for outbound filter/tunnel policy ID */
	u_int64_t policy_out;
	/** WFP allocated LUID for SA context */
	u_int64_t sa_id;
} entry_t;

/**
 * Create a SA/SP entry set
 */
static entry_t *entry_create(u_int32_t reqid, host_t *local, host_t *remote,
							 u_int8_t protocol, ipsec_mode_t mode, bool encap)
{
	entry_t *entry;

	INIT(entry,
		.reqid = reqid,
		.sas = array_create(0, 0),
		.sps = array_create(0, 0),
		.local = local->clone(local),
		.remote = remote->clone(remote),
		.protocol = protocol,
		.mode = mode,
		.encap = encap,
	);
	return entry;
}

/**
 * Destroy a SA/SP entry set
 */
static void entry_destroy(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (entry->sa_id)
	{
		IPsecSaContextDeleteById0(this->handle, entry->sa_id);
	}
	if (entry->policy_in)
	{
		FwpmFilterDeleteById0(this->handle, entry->policy_in);
	}
	if (entry->policy_out)
	{
		FwpmFilterDeleteById0(this->handle, entry->policy_out);
	}
	array_destroy(entry->sas);
	array_destroy(entry->sps);
	entry->local->destroy(entry->local);
	entry->remote->destroy(entry->remote);
	free(entry);
}

/**
 * Get an entry, create if not exists. May fail if non-matching entry found
 */
static entry_t *get_or_create_entry(private_kernel_wfp_ipsec_t *this,
							u_int32_t reqid, host_t *local, host_t *remote,
							u_int8_t protocol, ipsec_mode_t mode, bool encap)
{
	entry_t *entry;

	entry = this->entries->get(this->entries, (void*)(uintptr_t)reqid);
	if (!entry)
	{
		entry = entry_create(reqid, local, remote, protocol, mode, encap);
		this->entries->put(this->entries, (void*)(uintptr_t)reqid, entry);
		return entry;
	}
	if (entry->protocol == protocol &&
		entry->mode == mode &&
		entry->local->ip_equals(entry->local, local) &&
		entry->remote->ip_equals(entry->remote, remote))
	{
		return entry;
	}
	return NULL;
}

/**
 * Append/Realloc a filter condition to an existing condition set
 */
static FWPM_FILTER_CONDITION0 *append_condition(FWPM_FILTER_CONDITION0 *conds[],
												int *count)
{
	FWPM_FILTER_CONDITION0 *cond;

	(*count)++;
	*conds = realloc(*conds, *count * sizeof(*cond));
	cond = *conds + *count - 1;
	memset(cond, 0, sizeof(*cond));

	return cond;
}

/**
 * Convert an IPv4 prefix to a host order subnet mask
 */
static u_int32_t prefix2mask(u_int8_t prefix)
{
	u_int8_t netmask[4] = {};
	int i;

	for (i = 0; i < sizeof(netmask); i++)
	{
		if (prefix < 8)
		{
			netmask[i] = 0xFF << (8 - prefix);
			break;
		}
		netmask[i] = 0xFF;
		prefix -= 8;
	}
	return untoh32(netmask);
}

/**
 * Convert a 16-bit range to a WFP condition
 */
static void range2cond(FWPM_FILTER_CONDITION0 *cond,
					   u_int16_t from, u_int16_t to)
{
	if (from == to)
	{
		cond->matchType = FWP_MATCH_EQUAL;
		cond->conditionValue.type = FWP_UINT16;
		cond->conditionValue.uint16 = from;
	}
	else
	{
		cond->matchType = FWP_MATCH_RANGE;
		cond->conditionValue.type = FWP_RANGE_TYPE;
		cond->conditionValue.rangeValue = calloc(1, sizeof(FWP_RANGE0));
		cond->conditionValue.rangeValue->valueLow.type = FWP_UINT16;
		cond->conditionValue.rangeValue->valueLow.uint16 = from;
		cond->conditionValue.rangeValue->valueHigh.type = FWP_UINT16;
		cond->conditionValue.rangeValue->valueHigh.uint16 = to;
	}
}

/**
 * (Re-)allocate filter conditions for given local or remote traffic selector
 */
static bool ts2condition(traffic_selector_t *ts, bool local,
						 FWPM_FILTER_CONDITION0 *conds[], int *count)
{
	FWPM_FILTER_CONDITION0 *cond;
	FWP_BYTE_ARRAY16 *addr;
	FWP_RANGE0 *range;
	u_int16_t from_port, to_port;
	void *from, *to;
	u_int8_t proto;
	host_t *net;
	u_int8_t prefix;

	from = ts->get_from_address(ts).ptr;
	to = ts->get_to_address(ts).ptr;
	from_port = ts->get_from_port(ts);
	to_port = ts->get_to_port(ts);

	cond = append_condition(conds, count);
	if (local)
	{
		cond->fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
	}
	else
	{
		cond->fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	}
	if (ts->is_host(ts, NULL))
	{
		cond->matchType = FWP_MATCH_EQUAL;
		switch (ts->get_type(ts))
		{
			case TS_IPV4_ADDR_RANGE:
				cond->conditionValue.type = FWP_UINT32;
				cond->conditionValue.uint32 = untoh32(from);
				break;
			case TS_IPV6_ADDR_RANGE:
				cond->conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
				cond->conditionValue.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, from, sizeof(*addr));
				break;
			default:
				return FALSE;
		}
	}
	else if (ts->to_subnet(ts, &net, &prefix))
	{
		FWP_V6_ADDR_AND_MASK *m6;
		FWP_V4_ADDR_AND_MASK *m4;

		cond->matchType = FWP_MATCH_EQUAL;
		switch (net->get_family(net))
		{
			case AF_INET:
				cond->conditionValue.type = FWP_V4_ADDR_MASK;
				cond->conditionValue.v4AddrMask = m4 = calloc(1, sizeof(*m4));
				m4->addr = untoh32(from);
				m4->mask = prefix2mask(prefix);
				break;
			case AF_INET6:
				cond->conditionValue.type = FWP_V6_ADDR_MASK;
				cond->conditionValue.v6AddrMask = m6 = calloc(1, sizeof(*m6));
				memcpy(m6->addr, from, sizeof(m6->addr));
				m6->prefixLength = prefix;
				break;
			default:
				net->destroy(net);
				return FALSE;
		}
		net->destroy(net);
	}
	else
	{
		cond->matchType = FWP_MATCH_RANGE;
		cond->conditionValue.type = FWP_RANGE_TYPE;
		cond->conditionValue.rangeValue = range = calloc(1, sizeof(*range));
		switch (ts->get_type(ts))
		{
			case TS_IPV4_ADDR_RANGE:
				range->valueLow.type = FWP_UINT32;
				range->valueLow.uint32 = untoh32(from);
				range->valueHigh.type = FWP_UINT32;
				range->valueHigh.uint32 = untoh32(to);
				break;
			case TS_IPV6_ADDR_RANGE:
				range->valueLow.type = FWP_BYTE_ARRAY16_TYPE;
				range->valueLow.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, from, sizeof(*addr));
				range->valueHigh.type = FWP_BYTE_ARRAY16_TYPE;
				range->valueHigh.byteArray16 = addr = malloc(sizeof(*addr));
				memcpy(addr, to, sizeof(*addr));
				break;
			default:
				return FALSE;
		}
	}

	proto = ts->get_protocol(ts);
	if (proto && local)
	{
		cond = append_condition(conds, count);
		cond->fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		cond->matchType = FWP_MATCH_EQUAL;
		cond->conditionValue.type = FWP_UINT8;
		cond->conditionValue.uint8 = proto;
	}

	if (proto == IPPROTO_ICMP)
	{
		if (local)
		{
			u_int8_t from_type, to_type, from_code, to_code;

			from_type = traffic_selector_icmp_type(from_port);
			to_type = traffic_selector_icmp_type(to_port);
			from_code = traffic_selector_icmp_code(from_port);
			to_code = traffic_selector_icmp_code(to_port);

			if (from_type != 0 || to_type != 0xFF)
			{
				cond = append_condition(conds, count);
				cond->fieldKey = FWPM_CONDITION_ICMP_TYPE;
				range2cond(cond, from_type, to_type);
			}
			if (from_code != 0 || to_code != 0xFF)
			{
				cond = append_condition(conds, count);
				cond->fieldKey = FWPM_CONDITION_ICMP_CODE;
				range2cond(cond, from_code, to_code);
			}
		}
	}
	else if (from_port != 0 || to_port != 0xFFFF)
	{
		cond = append_condition(conds, count);
		if (local)
		{
			cond->fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
		}
		else
		{
			cond->fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		}
		range2cond(cond, from_port, to_port);
	}
	return TRUE;
}

/**
 * Free memory associated to a single condition
 */
static void free_condition(FWP_DATA_TYPE type, void *value)
{
	FWP_RANGE0 *range;

	switch (type)
	{
		case FWP_BYTE_ARRAY16_TYPE:
		case FWP_V4_ADDR_MASK:
		case FWP_V6_ADDR_MASK:
			free(value);
			break;
		case FWP_RANGE_TYPE:
			range = value;
			free_condition(range->valueLow.type, range->valueLow.sd);
			free_condition(range->valueHigh.type, range->valueHigh.sd);
			free(range);
			break;
		default:
			break;
	}
}

/**
 * Free memory used by a set of conditions
 */
static void free_conditions(FWPM_FILTER_CONDITION0 *conds, int count)
{
	int i;

	for (i = 0; i < count; i++)
	{
		free_condition(conds[i].conditionValue.type, conds[i].conditionValue.sd);
	}
	free(conds);
}

/**
 * Install transport mode SP to the kernel
 */
static bool install_transport_sp(private_kernel_wfp_ipsec_t *this,
								 entry_t *entry, bool inbound)
{
	FWPM_FILTER_CONDITION0 *conds = NULL;
	int count = 0;
	enumerator_t *enumerator;
	traffic_selector_t *local, *remote;
	sp_entry_t *sp;
	DWORD res;
	FWPM_FILTER0 filter = {
		.displayData = {
			.name = L"charon IPsec transport",
		},
		.action = {
			.type = FWP_ACTION_CALLOUT_TERMINATING,
			.calloutKey = inbound ? FWPM_CALLOUT_IPSEC_INBOUND_TRANSPORT_V4 :
									FWPM_CALLOUT_IPSEC_OUTBOUND_TRANSPORT_V4,
		},
		.layerKey = inbound ? FWPM_LAYER_INBOUND_TRANSPORT_V4 :
							  FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
	};

	enumerator = array_create_enumerator(entry->sps);
	while (enumerator->enumerate(enumerator, &sp))
	{
		if (inbound)
		{
			if (sp->direction != POLICY_IN)
			{
				continue;
			}
			local = sp->dst;
			remote = sp->src;
		}
		else
		{
			if (sp->direction != POLICY_OUT)
			{
				continue;
			}
			local = sp->src;
			remote = sp->dst;
		}

		if (!ts2condition(local, TRUE, &conds, &count) ||
			!ts2condition(remote, FALSE, &conds, &count))
		{
			free_conditions(conds, count);
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);

	filter.numFilterConditions = count;
	filter.filterCondition = conds;

	if (inbound)
	{
		res = FwpmFilterAdd0(this->handle, &filter, NULL, &entry->policy_in);
	}
	else
	{
		res = FwpmFilterAdd0(this->handle, &filter, NULL, &entry->policy_out);
	}
	free_conditions(conds, count);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "installing inbound FWP filter failed: 0x%08x", res);
		return FALSE;
	}
	return TRUE;
}

/**
 * Convert a chunk_t to a WFP FWP_BYTE_BLOB
 */
static inline FWP_BYTE_BLOB chunk2blob(chunk_t chunk)
{
	return (FWP_BYTE_BLOB){
		.size = chunk.len,
		.data = chunk.ptr,
	};
}

/**
 * Convert an integrity_algorithm_t to a WFP IPSEC_AUTH_TRANFORM_ID0
 */
static bool alg2auth(integrity_algorithm_t alg,
					 IPSEC_SA_AUTH_INFORMATION0 *info)
{
	struct {
		integrity_algorithm_t alg;
		IPSEC_AUTH_TRANSFORM_ID0 transform;
	} map[] = {
		{ AUTH_HMAC_MD5_96,			IPSEC_AUTH_TRANSFORM_ID_HMAC_MD5_96		},
		{ AUTH_HMAC_SHA1_96,		IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_1_96	},
		{ AUTH_HMAC_SHA2_256_128,	IPSEC_AUTH_TRANSFORM_ID_HMAC_SHA_256_128},
		{ AUTH_AES_128_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_128		},
		{ AUTH_AES_192_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_192		},
		{ AUTH_AES_256_GMAC,		IPSEC_AUTH_TRANSFORM_ID_GCM_AES_256		},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].alg == alg)
		{
			info->authTransform.authTransformId = map[i].transform;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Convert an encryption_algorithm_t to a WFP IPSEC_CIPHER_TRANFORM_ID0
 */
static bool alg2cipher(encryption_algorithm_t alg, int keylen,
					   IPSEC_SA_CIPHER_INFORMATION0 *info)
{
	struct {
		encryption_algorithm_t alg;
		int keylen;
		IPSEC_CIPHER_TRANSFORM_ID0 transform;
	} map[] = {
		{ ENCR_DES,				 8, IPSEC_CIPHER_TRANSFORM_ID_CBC_DES		},
		{ ENCR_3DES,			24, IPSEC_CIPHER_TRANSFORM_ID_CBC_3DES		},
		{ ENCR_AES_CBC,			16, IPSEC_CIPHER_TRANSFORM_ID_AES_128		},
		{ ENCR_AES_CBC,			24, IPSEC_CIPHER_TRANSFORM_ID_AES_192		},
		{ ENCR_AES_CBC,			32, IPSEC_CIPHER_TRANSFORM_ID_AES_256		},
		{ ENCR_AES_GCM_ICV16,	20, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_128	},
		{ ENCR_AES_GCM_ICV16,	28, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_192	},
		{ ENCR_AES_GCM_ICV16,	36, IPSEC_CIPHER_TRANSFORM_ID_GCM_AES_256	},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].alg == alg && map[i].keylen == keylen)
		{
			info->cipherTransform.cipherTransformId = map[i].transform;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Get the integrity algorithm used for an AEAD transform
 */
static integrity_algorithm_t encr2integ(encryption_algorithm_t encr, int keylen)
{
	struct {
		encryption_algorithm_t encr;
		int keylen;
		integrity_algorithm_t integ;
	} map[] = {
		{ ENCR_NULL_AUTH_AES_GMAC,		20, AUTH_AES_128_GMAC				},
		{ ENCR_NULL_AUTH_AES_GMAC,		28, AUTH_AES_192_GMAC				},
		{ ENCR_NULL_AUTH_AES_GMAC,		36, AUTH_AES_256_GMAC				},
		{ ENCR_AES_GCM_ICV16,			20, AUTH_AES_128_GMAC				},
		{ ENCR_AES_GCM_ICV16,			28, AUTH_AES_192_GMAC				},
		{ ENCR_AES_GCM_ICV16,			36, AUTH_AES_256_GMAC				},
	};
	int i;

	for (i = 0; i < countof(map); i++)
	{
		if (map[i].encr == encr && map[i].keylen == keylen)
		{
			return map[i].integ;
		}
	}
	return AUTH_UNDEFINED;
}

/**
 * Install a single transport mode SA
 */
static bool install_transport_sa(private_kernel_wfp_ipsec_t *this,
						entry_t *entry, sa_entry_t *sa, FWP_IP_VERSION version)
{
	IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0 info = {};
	IPSEC_SA0 ipsec = {
		.spi = ntohl(sa->spi),
	};
	IPSEC_SA_BUNDLE0 bundle = {
		.saList = &ipsec,
		.numSAs = 1,
		.ipVersion = version,
	};
	struct {
		u_int16_t alg;
		chunk_t key;
	} integ = {}, encr = {};
	DWORD res;

	switch (entry->protocol)
	{
		case IPPROTO_AH:
			ipsec.saTransformType = IPSEC_TRANSFORM_AH;
			ipsec.ahInformation = &info.saAuthInformation;
			integ.key = sa->integ.key;
			integ.alg = sa->integ.alg;
			break;
		case IPPROTO_ESP:
			if (sa->encr.alg == ENCR_NULL ||
				sa->encr.alg == ENCR_NULL_AUTH_AES_GMAC)
			{
				ipsec.saTransformType = IPSEC_TRANSFORM_ESP_AUTH;
				ipsec.espAuthInformation = &info.saAuthInformation;
			}
			else
			{
				ipsec.saTransformType = IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER;
				ipsec.espAuthAndCipherInformation = &info;
				encr.key = sa->encr.key;
				encr.alg = sa->encr.alg;
			}
			if (encryption_algorithm_is_aead(sa->encr.alg))
			{
				integ.alg = encr2integ(sa->encr.alg, sa->encr.key.len);
				integ.key = sa->encr.key;
			}
			else
			{
				integ.alg = sa->integ.alg;
				integ.key = sa->integ.key;
			}
			break;
		default:
			return FALSE;
	}

	if (integ.alg)
	{
		info.saAuthInformation.authKey = chunk2blob(integ.key);
		if (!alg2auth(integ.alg, &info.saAuthInformation))
		{
			DBG1(DBG_KNL, "integrity algorithm %N not supported by WFP",
				 integrity_algorithm_names, integ.alg);
			return FALSE;
		}
	}
	if (encr.alg)
	{
		info.saCipherInformation.cipherKey = chunk2blob(encr.key);
		if (!alg2cipher(encr.alg, encr.key.len, &info.saCipherInformation))
		{
			DBG1(DBG_KNL, "encryption algorithm %N not supported by WFP",
				 encryption_algorithm_names, encr.alg);
			return FALSE;
		}
	}

	if (sa->inbound)
	{
		res = IPsecSaContextAddInbound0(this->handle, entry->sa_id, &bundle);
	}
	else
	{
		res = IPsecSaContextAddOutbound0(this->handle, entry->sa_id, &bundle);
	}
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "adding %sbound WFP SA failed: 0x%08x",
			 sa->inbound ? "in" : "out", res);
		return FALSE;
	}
	return TRUE;
}

/**
 * Install transport mode SAs to the kernel
 */
static bool install_transport_sas(private_kernel_wfp_ipsec_t *this,
								  entry_t *entry)
{
	IPSEC_TRAFFIC0 traffic = {
		.trafficType = IPSEC_TRAFFIC_TYPE_TRANSPORT,
	};
	IPSEC_GETSPI1 spi = {
		.inboundIpsecTraffic = {
			.trafficType = IPSEC_TRAFFIC_TYPE_TRANSPORT,
			.ipsecFilterId = entry->policy_in,
		},
	};
	sa_entry_t *sa;
	IPSEC_SA_SPI inbound_spi = 0;
	enumerator_t *enumerator;
	DWORD res;

	switch (entry->local->get_family(entry->local))
	{
		case AF_INET:
			traffic.ipVersion = FWP_IP_VERSION_V4;
			traffic.localV4Address =
						untoh32(entry->local->get_address(entry->local).ptr);
			traffic.remoteV4Address =
						untoh32(entry->remote->get_address(entry->remote).ptr);
			break;
		case AF_INET6:
			traffic.ipVersion = FWP_IP_VERSION_V6;
			memcpy(&traffic.localV6Address,
				   entry->local->get_address(entry->local).ptr, 16);
			memcpy(&traffic.remoteV6Address,
				   entry->remote->get_address(entry->remote).ptr, 16);
			break;
		default:
			return FALSE;
	}

	traffic.ipsecFilterId = entry->policy_out;
	res = IPsecSaContextCreate0(this->handle, &traffic, NULL, &entry->sa_id);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "creating WFP SA context failed: 0x%08x", res);
		return FALSE;
	}

	enumerator = array_create_enumerator(entry->sas);
	while (enumerator->enumerate(enumerator, &sa))
	{
		if (sa->inbound)
		{
			inbound_spi = ntohl(sa->spi);
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!inbound_spi)
	{
		return FALSE;
	}

	memcpy(spi.inboundIpsecTraffic.localV6Address, traffic.localV6Address,
		   sizeof(traffic.localV6Address));
	memcpy(spi.inboundIpsecTraffic.remoteV6Address, traffic.remoteV6Address,
		   sizeof(traffic.remoteV6Address));
	spi.ipVersion = traffic.ipVersion;

	res = IPsecSaContextSetSpi0(this->handle, entry->sa_id, &spi, inbound_spi);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "setting WFP SA SPI failed: 0x%08x", res);
		IPsecSaContextDeleteById0(this->handle, entry->sa_id);
		entry->sa_id = 0;
		return FALSE;
	}

	enumerator = array_create_enumerator(entry->sas);
	while (enumerator->enumerate(enumerator, &sa))
	{
		if (!install_transport_sa(this, entry, sa, spi.ipVersion))
		{
			enumerator->destroy(enumerator);
			IPsecSaContextDeleteById0(this->handle, entry->sa_id);
			entry->sa_id = 0;
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);

	return TRUE;
}

/**
 * Install a transport mode SA/SP set to the kernel
 */
static bool install_transport(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	if (install_transport_sp(this, entry, TRUE) &&
		install_transport_sp(this, entry, FALSE) &&
		install_transport_sas(this, entry))
	{
		return TRUE;
	}
	if (entry->policy_in)
	{
		FwpmFilterDeleteById0(this->handle, entry->policy_in);
		entry->policy_in = 0;
	}
	if (entry->policy_out)
	{
		FwpmFilterDeleteById0(this->handle, entry->policy_out);
		entry->policy_out = 0;
	}
	return FALSE;
}

/**
 * Install a SA/SP set to the kernel
 */
static bool install(private_kernel_wfp_ipsec_t *this, entry_t *entry)
{
	switch (entry->mode)
	{
		case MODE_TRANSPORT:
			return install_transport(this, entry);
		case MODE_TUNNEL:
		case MODE_BEET:
		default:
			return FALSE;
	}
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_wfp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	*spi = ref_get(&this->nextspi);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool initiator, bool encap, bool esn, bool inbound,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	status_t status = SUCCESS;
	host_t *local, *remote;
	entry_t *entry;
	sa_entry_t *sa;

	if (inbound)
	{
		local = dst;
		remote = src;
	}
	else
	{
		local = src;
		remote = dst;
	}

	this->mutex->lock(this->mutex);
	entry = get_or_create_entry(this, reqid, local, remote,
								protocol, mode, encap);
	if (entry)
	{
		INIT(sa,
			.spi = spi,
			.inbound = inbound,
			.dst = inbound ? entry->local : entry->remote,
			.encr = {
				.alg = enc_alg,
				.key = chunk_clone(enc_key),
			},
			.integ = {
				.alg = int_alg,
				.key = chunk_clone(int_key),
			},
		);
		array_insert(entry->sas, -1, sa);
		this->sas->put(this->sas, sa, entry);
	}
	else
	{
		DBG1(DBG_KNL, "adding SA failed, a different SA with reqid %u exists",
			 reqid);
		status = FAILED;
	}
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_wfp_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap, mark_t mark)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes,
	u_int64_t *packets, time_t *time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	status_t status = NOT_FOUND;
	entry_t *entry;
	host_t *local, *remote;
	enumerator_t *enumerator;
	sa_entry_t *sa, key = {
		.dst = dst,
		.spi = spi,
	};

	this->mutex->lock(this->mutex);

	entry = this->sas->get(this->sas, &key);
	if (entry)
	{
		enumerator = array_create_enumerator(entry->sas);
		while (enumerator->enumerate(enumerator, &sa))
		{
			if (sa->inbound)
			{
				local = dst;
				remote = src;
			}
			else
			{
				local = src;
				remote = dst;
			}
			if (sa->spi == spi && entry->protocol == protocol &&
				local->ip_equals(local, entry->local) &&
				remote->ip_equals(remote, entry->remote))
			{
				array_remove_at(entry->sas, enumerator);
				this->sas->remove(this->sas, sa);
				/* TODO: uninstall SA from kernel */
				sa_entry_destroy(sa);
				status = SUCCESS;
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (!array_count(entry->sas) && !array_count(entry->sps))
		{
			entry = this->entries->remove(this->entries,
										  (void*)(uintptr_t)entry->reqid);
			if (entry)
			{
				entry_destroy(this, entry);
			}
		}
	}

	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa, mark_t mark,
	policy_priority_t priority)
{
	status_t status = SUCCESS;
	host_t *local, *remote;
	entry_t *entry;
	sp_entry_t *sp;

	if (direction == POLICY_FWD || priority != POLICY_PRIORITY_DEFAULT)
	{
		return SUCCESS;
	}

	if (direction == POLICY_IN)
	{
		local = dst;
		remote = src;
	}
	else
	{
		local = src;
		remote = dst;
	}

	this->mutex->lock(this->mutex);
	entry = get_or_create_entry(this, sa->reqid, local, remote,
								sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
								sa->mode, FALSE);
	if (entry)
	{
		INIT(sp,
			.src = src_ts->clone(src_ts),
			.dst = dst_ts->clone(dst_ts),
			.direction = direction,
		);
		array_insert(entry->sps, -1, sp);
		if (array_count(entry->sps) > 1)
		{
			if (!install(this, entry))
			{
				status = FAILED;
			}
		}
	}
	else
	{
		DBG1(DBG_KNL, "adding SP failed, a different SP with reqid %u exists",
			 sa->reqid);
		status = FAILED;
	}
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t priority)
{
	status_t status = NOT_FOUND;
	entry_t *entry;
	sp_entry_t *sp;
	enumerator_t *enumerator;

	this->mutex->lock(this->mutex);

	entry = this->entries->get(this->entries, (void*)(uintptr_t)reqid);
	if (entry)
	{
		enumerator = array_create_enumerator(entry->sps);
		while (enumerator->enumerate(enumerator, &sp))
		{
			if (sp->direction == direction &&
				src_ts->equals(src_ts, sp->src) &&
				dst_ts->equals(dst_ts, sp->dst))
			{
				array_remove_at(entry->sps, enumerator);
				/* TODO: uninstall SP from kernel */
				sp_entry_destroy(sp);
				status = SUCCESS;
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (!array_count(entry->sas) && !array_count(entry->sps))
		{
			entry = this->entries->remove(this->entries,
										  (void*)(uintptr_t)reqid);
			if (entry)
			{
				entry_destroy(this, entry);
			}
		}
	}

	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_wfp_ipsec_t *this)
{
	if (this->handle)
	{
		FwpmEngineClose0(this->handle);
	}
	this->entries->destroy(this->entries);
	this->sas->destroy(this->sas);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_wfp_ipsec_t *kernel_wfp_ipsec_create()
{
	private_kernel_wfp_ipsec_t *this;
	DWORD res;
	FWPM_SESSION0 session = {
		.displayData = {
			.name = L"charon",
			.description = L"strongSwan IKE kernel-wfp backend",
		},
	};

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.nextspi = htonl(0xc0000001),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.entries = hashtable_create(hashtable_hash_ptr,
									hashtable_equals_ptr, 4),
		.sas = hashtable_create((void*)hash_sa, (void*)equals_sa, 4),
	);

	res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
						  &this->handle);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "opening WFP engine failed: 0x%08x", res);
		destroy(this);
		return NULL;
	}

	return &this->public;
}
