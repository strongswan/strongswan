/*
 * Copyright (C) 2023 Tobias Brunner
 * Copyright (c) 2022 Nanoteq Pty Ltd
 *
 * Copyright (C) secunet Security Networks AG
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

#include "kernel_vpp_ipsec.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/hashtable.h>
#include <processing/jobs/callback_job.h>

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/ipsec.api.vapi.h>
#include <vnet/vnet.h>
#include <vpp-api/client/stat_client.h>
#include <vppinfra/vec.h>

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_IPSEC_API_JSON

#define SA_STAT_SEGMENT_NAME "/net/ipsec/sa"

/* default values for config options */
#define VPP_APP_NAME "strongswan"
#define VPP_MAX_OUTSTANDING_REQUESTS 64
#define VPP_RESPONSE_QUEUE_SIZE 32

/** base priority for installed policies */
#define POLICY_PRIO_BASE 200000

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private data
 */
struct private_kernel_vpp_ipsec_t
{
	/**
	 * Public interface
	 */
	kernel_vpp_ipsec_t public;

	/**
	 * Mutex for accessing entries
	 */
	mutex_t *mutex;

	/**
	 * Next security association database entry ID to allocate
	 */
	refcount_t next_sad_id;

	/**
	 * Security policy database entry ID used for policies
	 */
	refcount_t spd_id;

	/**
	 * Hash table of IPsec SAs using policies (sa_t)
	 */
	hashtable_t *sas;

	/**
	 * RNG used to generate SPIs
	 */
	rng_t *rng;

	/**
	 * VPP API Context
	 */
	vapi_ctx_t vpp_ctx;
};

/**
 * Destroy the given SA ID object
 */
static void ipsec_sa_id_destroy(kernel_ipsec_sa_id_t *id)
{
	id->src->destroy(id->src);
	id->dst->destroy(id->dst);
	free(id);
}

/**
 * Clone the given SA ID object
 */
static kernel_ipsec_sa_id_t *ipsec_sa_id_clone(kernel_ipsec_sa_id_t *id)
{
	kernel_ipsec_sa_id_t *clone = malloc_thing(kernel_ipsec_sa_id_t);

	*clone = *id;
	clone->src = clone->src->clone(clone->src);
	clone->dst = clone->dst->clone(clone->dst);
	return clone;
}

/**
 * Hash function for IPsec SA entries
 */
static u_int ipsec_sa_id_hash(kernel_ipsec_sa_id_t *sa)
{
	return chunk_hash_inc(sa->src->get_address(sa->src),
						  chunk_hash_inc(sa->dst->get_address(sa->dst),
						  chunk_hash_inc(chunk_from_thing(sa->spi),
						  chunk_hash(chunk_from_thing(sa->proto)))));
}

/**
 * Equality function for IPsec SA entries
 */
static bool ipsec_sa_id_equals(kernel_ipsec_sa_id_t *sa,
							   kernel_ipsec_sa_id_t *other_sa)
{
	return sa->src->ip_equals(sa->src, other_sa->src) &&
		   sa->dst->ip_equals(sa->dst, other_sa->dst) &&
		   sa->spi == other_sa->spi &&
		   sa->proto == other_sa->proto;
}

/**
 * IPsec SA entry
 */
typedef struct {
	/** SA ID */
	kernel_ipsec_sa_id_t *id;
	/** VPP SA ID */
	uint32_t sa_id;
	/** VPP stats index for the SA */
	uint32_t stat_index;
} sa_t;

/**
 * Destroy an sa_t object
 */
static void sa_destroy(sa_t *sa)
{
	ipsec_sa_id_destroy(sa->id);
	free(sa);
}

/**
 * Calculate the approximate prefix length for the port range in the given TS
 */
static uint8_t port_range_prefix(traffic_selector_t *ts)
{
	uint16_t from, to, bitmask = 0x8000;
	uint8_t prefix;

	from = ts->get_from_port(ts);
	to = ts->get_to_port(ts);

	for (prefix = 0; prefix < 16; prefix++)
	{
		if ((bitmask & from) != (bitmask & to))
		{
			break;
		}
		bitmask >>= 1;
	}
	return prefix;
}

/**
 * Calculate the priority of a policy
 *
 * This is basically the same formula we use in the kernel-netlink interface,
 * but some features are currently not or only partially supported by VPP.
 *
 * Note that larger values have a higher precedence in VPP as compared to the
 * Linux kernel.
 *
 * bits 0-0:  separate trap and regular policies (0..1)     1 bit
 * bits 1-1:  reserved for interface restriction (0..1)     1 bit
 * bits 2-7:  src + dst port mask bits (2 * 0..16)          6 bits
 * bits 8-8:  restriction to protocol (0..1)                1 bit
 * bits 9-17: src + dst network mask bits (2 * 0..128)      9 bits
 *                                                         18 bits
 *
 * smallest value: 000000000 0 000000 0 0:       0, lowest priority  = 200'000
 * largest value : 100000000 1 100000 0 1: 131'457, highest priority = 731'457
 */
static uint32_t get_priority(kernel_ipsec_policy_id_t *id,
							 policy_priority_t prio)
{
	uint32_t priority = POLICY_PRIO_BASE;
	uint8_t proto, src_prefix, dst_prefix, sport_prefix, dport_prefix;

	switch (prio)
	{
		case POLICY_PRIORITY_PASS:
			priority += POLICY_PRIO_BASE;
			/* fall-through */
		case POLICY_PRIORITY_ROUTED:
		case POLICY_PRIORITY_DEFAULT:
			priority += POLICY_PRIO_BASE;
			/* fall-through */
		case POLICY_PRIORITY_FALLBACK:
			break;
	}

	/* since VPP supports ranges, these prefixes are just approximations */
	id->src_ts->to_subnet(id->src_ts, NULL, &src_prefix);
	id->dst_ts->to_subnet(id->dst_ts, NULL, &dst_prefix);
	sport_prefix = port_range_prefix(id->src_ts);
	dport_prefix = port_range_prefix(id->dst_ts);

	proto = max(id->src_ts->get_protocol(id->src_ts),
				id->dst_ts->get_protocol(id->dst_ts));

	/* calculate priority */
	priority += (src_prefix + dst_prefix) * 512;
	priority += proto ? 256 : 0;
	priority += (sport_prefix + dport_prefix) * 4;
	priority += (prio != POLICY_PRIORITY_ROUTED);
	return priority;
}

/**
 * Convert a chunk containing an IP address to a VPP address
 */
static inline void chunk_to_vapi_addr(chunk_t chunk, vapi_type_address *addr)
{
	addr->af = (chunk.len == 4) ? ADDRESS_IP4 : ADDRESS_IP6;
	memcpy(&addr->un, chunk.ptr, chunk.len);
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_vpp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	uint32_t spi_min, spi_max, spi_new;

	spi_min = lib->settings->get_int(lib->settings, "%s.spi_min",
									 KERNEL_SPI_MIN, lib->ns);
	spi_max = lib->settings->get_int(lib->settings, "%s.spi_max",
									 KERNEL_SPI_MAX, lib->ns);
	if (spi_min > spi_max)
	{
		spi_new = spi_min;
		spi_min = spi_max;
		spi_max = spi_new;
	}
	/* make sure the SPI is valid (not in range 0-255) */
	spi_min = max(spi_min, 0x00000100);
	spi_max = max(spi_max, 0x00000100);

	if (!this->rng->get_bytes(this->rng, sizeof(spi_new),
							  (uint8_t*)&spi_new))
	{
		DBG1(DBG_KNL, "failed to allocate SPI");
		return FAILED;
	}
	spi_new = spi_min + spi_new % (spi_max - spi_min + 1);

	DBG2(DBG_KNL, "allocated SPI %.8x", spi_new);
	*spi = htonl(spi_new);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	/* IPComp is not supported in VPP */
	return NOT_SUPPORTED;
}

/**
 * Data for an expire callback job
 */
typedef struct {
	/** Reference to kernel interface */
	private_kernel_vpp_ipsec_t *this;
	/** SA to expire */
	kernel_ipsec_sa_id_t *id;
	/** 0 if this is a hard expire, otherwise the offset in s (soft->hard) */
	uint32_t hard_offset;
} expire_data_t;

/**
 * Clean up expire data
 */
CALLBACK(expire_data_destroy, void,
	expire_data_t *this)
{
	ipsec_sa_id_destroy(this->id);
	free(this);
}

CALLBACK(expire_job, job_requeue_t,
	expire_data_t *data)
{
	private_kernel_vpp_ipsec_t *this = data->this;
	uint32_t hard_offset = 0;
	sa_t *entry;

	this->mutex->lock(this->mutex);
	entry = this->sas->get(this->sas, data->id);
	if (entry)
	{
		hard_offset = data->hard_offset;
		if (hard_offset)
		{
			/* soft limit reached, schedule hard expire */
			data->hard_offset = 0;
		}
	}
	this->mutex->unlock(this->mutex);

	if (entry)
	{
		charon->kernel->expire(charon->kernel, data->id->proto, data->id->spi,
							   data->id->dst, !hard_offset);
	}
	return hard_offset ? JOB_RESCHEDULE(hard_offset) : JOB_REQUEUE_NONE;
}

/**
 * Schedule an expire event for the given SA
 */
static void schedule_expire(private_kernel_vpp_ipsec_t *this,
							kernel_ipsec_sa_id_t *id, lifetime_cfg_t *lifetime)
{
	expire_data_t *data;
	callback_job_t *job;
	uint32_t timeout;

	if (!lifetime->time.life)
	{	/* no expiration at all */
		return;
	}

	INIT(data,
		.this = this,
		.id = ipsec_sa_id_clone(id),
	);

	/* schedule a rekey first, a hard timeout will be scheduled then, if any */
	data->hard_offset = lifetime->time.life - lifetime->time.rekey;
	timeout = lifetime->time.rekey;

	if (lifetime->time.life <= lifetime->time.rekey ||
		lifetime->time.rekey == 0)
	{	/* no rekey, schedule hard timeout */
		data->hard_offset = 0;
		timeout = lifetime->time.life;
	}

	job = callback_job_create(expire_job, data, expire_data_destroy, NULL);
	lib->scheduler->schedule_job(lib->scheduler, (job_t*)job, timeout);
}

/**
 * Map the given protocol to a supported VPP identifier
 */
static vapi_enum_ipsec_proto map_protocol(uint8_t proto)
{
	switch (proto)
	{
		case IPPROTO_ESP:
			return IPSEC_API_PROTO_ESP;
		case IPPROTO_AH:
			return IPSEC_API_PROTO_AH;
		default:
			return -1;
	}
}

/**
 * Map of supported encryption/AEAD algorithms
 */
static struct {
	encryption_algorithm_t alg;
	size_t key_len;
	size_t salt_len;
	vapi_enum_ipsec_crypto_alg api;
} enc_algs[] = {
	{ENCR_NULL,					0,	0,	IPSEC_API_CRYPTO_ALG_NONE},
	{ENCR_DES,					0,	0,	IPSEC_API_CRYPTO_ALG_DES_CBC},
	{ENCR_3DES,					0,	0,	IPSEC_API_CRYPTO_ALG_3DES_CBC},
	{ENCR_AES_CBC,				16,	0,	IPSEC_API_CRYPTO_ALG_AES_CBC_128},
	{ENCR_AES_CBC,				24,	0,	IPSEC_API_CRYPTO_ALG_AES_CBC_192},
	{ENCR_AES_CBC,				32,	0,	IPSEC_API_CRYPTO_ALG_AES_CBC_256},
	{ENCR_AES_CTR,				16,	4,	IPSEC_API_CRYPTO_ALG_AES_CTR_128},
	{ENCR_AES_CTR,				24,	4,	IPSEC_API_CRYPTO_ALG_AES_CTR_192},
	{ENCR_AES_CTR,				32,	4,	IPSEC_API_CRYPTO_ALG_AES_CTR_256},
	/* only a 128-bit ICV seems to be supported by VPP for AES-GCM */
	{ENCR_AES_GCM_ICV16,		16,	4,	IPSEC_API_CRYPTO_ALG_AES_GCM_128},
	{ENCR_AES_GCM_ICV16,		24,	4,	IPSEC_API_CRYPTO_ALG_AES_GCM_192},
	{ENCR_AES_GCM_ICV16,		32,	4,	IPSEC_API_CRYPTO_ALG_AES_GCM_256},
	{ENCR_CHACHA20_POLY1305,	32,	4,	IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305},
};

/**
 * Map the given algorithm and key size to an identifier
 */
static vapi_enum_ipsec_crypto_alg map_enc_alg(encryption_algorithm_t alg,
											  size_t key_len, size_t *salt_len)
{
	int i;

	for (i = 0; i < countof(enc_algs); i++)
	{
		if (enc_algs[i].alg == alg &&
			(!enc_algs[i].key_len ||
			 (enc_algs[i].key_len + enc_algs[i].salt_len) == key_len))
		{
			*salt_len = enc_algs[i].salt_len;
			return enc_algs[i].api;
		}
	}
	return -1;
}

/**
 * Map of supported integrity protection algorithms
 */
static struct {
	integrity_algorithm_t alg;
	vapi_enum_ipsec_integ_alg api;
} int_algs[] = {
	{AUTH_HMAC_MD5_96,			IPSEC_API_INTEG_ALG_MD5_96},
	{AUTH_HMAC_SHA1_96,			IPSEC_API_INTEG_ALG_SHA1_96},
	{AUTH_HMAC_SHA2_256_96,		IPSEC_API_INTEG_ALG_SHA_256_96},
	{AUTH_HMAC_SHA2_256_128,	IPSEC_API_INTEG_ALG_SHA_256_128},
	{AUTH_HMAC_SHA2_384_192,	IPSEC_API_INTEG_ALG_SHA_384_192},
	{AUTH_HMAC_SHA2_512_256,	IPSEC_API_INTEG_ALG_SHA_512_256},
};

/**
 * Map the given algorithm to an identifier
 */
static vapi_enum_ipsec_integ_alg map_int_alg(integrity_algorithm_t alg)
{
	int i;

	for (i = 0; i < countof(int_algs); i++)
	{
		if (int_algs[i].alg == alg)
		{
			return int_algs[i].api;
		}
	}
	return -1;
}

/**
 * Callback for adding/deleting SAs
 */
static vapi_error_e add_del_sad_cb(vapi_ctx_t ctx, void *user, vapi_error_e rv,
								   bool is_last,
								   vapi_payload_ipsec_sad_entry_add_del_v2_reply *p)
{
	vapi_payload_ipsec_sad_entry_add_del_v2_reply *reply = user;

	if (p)
	{
		*reply = *p;
	}
	else
	{
		reply->retval = VNET_API_ERROR_RESPONSE_NOT_READY;
	}
	return VAPI_OK;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	vapi_error_e rv;
	vapi_msg_ipsec_sad_entry_add_del_v2 *msg;
	vapi_type_ipsec_sad_entry_v2 *entry;
	vapi_payload_ipsec_sad_entry_add_del_v2_reply reply;
	uint32_t sad_id, flags = IPSEC_API_SAD_FLAG_NONE;
	size_t salt_len = 0;
	sa_t *sa;

	msg = vapi_alloc_ipsec_sad_entry_add_del_v2(this->vpp_ctx);
	msg->payload.is_add = TRUE;
	entry = &msg->payload.entry;

	entry->sad_id = sad_id = ref_get(&this->next_sad_id);
	entry->spi = ntohl(id->spi);

	DBG2(DBG_KNL, "adding SAD entry with SPI %.8x and ID %d",
		 ntohl(id->spi), sad_id);

	entry->protocol = map_protocol(id->proto);
	if (entry->protocol == -1)
	{
		DBG1(DBG_KNL, "unsupported IPsec protocol %d", id->proto);
		vapi_msg_free(this->vpp_ctx, msg);
		return FAILED;
	}

	if (data->enc_alg != ENCR_UNDEFINED)
	{
		entry->crypto_algorithm = map_enc_alg(data->enc_alg,
											  data->enc_key.len, &salt_len);
		if (entry->crypto_algorithm == -1)
		{
			DBG1(DBG_KNL, "algorithm %N with key size %u not supported by VPP",
				 encryption_algorithm_names, data->enc_alg,
				 data->enc_key.len * 8);
			vapi_msg_free(this->vpp_ctx, msg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
			 encryption_algorithm_names, data->enc_alg, data->enc_key.len * 8);

		entry->crypto_key.length = min(sizeof(entry->crypto_key.data),
									   data->enc_key.len - salt_len);
		memcpy(entry->crypto_key.data, data->enc_key.ptr,
			   entry->crypto_key.length);
		/* VPP uses an uint32_t as salt, which is the only length we currently
		 * support, but the VAPI layer will convert the byte order */
		if (salt_len == 4)
		{
			entry->salt = untoh32(data->enc_key.ptr + entry->crypto_key.length);
		}
	}

	if (data->int_alg != AUTH_UNDEFINED)
	{
		entry->integrity_algorithm = map_int_alg(data->int_alg);
		if (entry->integrity_algorithm == 1)
		{
			DBG1(DBG_KNL, "algorithm %N not supported by VPP",
				 integrity_algorithm_names, data->int_alg);
			vapi_msg_free(this->vpp_ctx, msg);
			return FAILED;
		}
		DBG2(DBG_KNL, "  using integrity algorithm %N with key size %d",
			 integrity_algorithm_names, data->int_alg, data->int_key.len * 8);

		entry->integrity_key.length = min(sizeof(entry->integrity_key.data),
										  data->int_key.len);
		memcpy(entry->integrity_key.data, data->int_key.ptr,
			   entry->integrity_key.length);
	}

	if (data->esn)
	{
		flags |= IPSEC_API_SAD_FLAG_USE_ESN;
	}
	if (data->mode == MODE_TUNNEL)
	{
		flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
		if (id->src->get_family(id->src) == AF_INET6)
		{
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
		}
	}
	if (data->encap)
	{
		flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
		entry->udp_src_port = id->src->get_port(id->src);
		entry->udp_dst_port = id->dst->get_port(id->dst);
	}
	if (data->inbound)
	{
		flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;

		if (data->replay_window)
		{
			flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
		}
	}
	entry->flags = flags;

	if (data->copy_df)
	{
		entry->tunnel_flags |= TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF;
	}
	if (data->copy_ecn)
	{
		entry->tunnel_flags |= TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN |
							   TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN;
	}
	if (data->copy_dscp)
	{
		entry->tunnel_flags |= TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP;
	}

	chunk_to_vapi_addr(id->src->get_address(id->src), &entry->tunnel_src);
	chunk_to_vapi_addr(id->dst->get_address(id->dst), &entry->tunnel_dst);

	rv = vapi_ipsec_sad_entry_add_del_v2(this->vpp_ctx, msg, add_del_sad_cb,
										 &reply);
	if (rv != VAPI_OK || reply.retval)
	{
		DBG1(DBG_KNL, "unable to add SAD entry with SPI %.8x (%d)",
			 ntohl(id->spi), rv ?: reply.retval);
		return FAILED;
	}

	INIT(sa,
		.id = ipsec_sa_id_clone(id),
		.sa_id = sad_id,
		.stat_index = reply.stat_index,
	);

	this->mutex->lock(this->mutex);
	this->sas->put(this->sas, sa->id, sa);
	schedule_expire(this, id, data->lifetime);
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	/* this is not currently supported by VPP */
	return NOT_SUPPORTED;
}

/**
 * Get the VPP statistics for a particular segment
 */
static stat_segment_data_t *get_vpp_statistics(char *segment_name)
{
	uint8_t **pattern = NULL;
	stat_segment_data_t *result;
	uint32_t *dir;
	int rv;

	rv = stat_segment_connect(STAT_SEGMENT_SOCKET_FILE);
	if (rv != 0)
	{
		DBG1(DBG_KNL, "unable to connect to VPP stats socket (%d)", rv);
		return NULL;
	}

	vec_add1(pattern, segment_name);
	dir = stat_segment_ls(pattern);
	result = stat_segment_dump(dir);
	vec_free(dir);
	vec_free(pattern);

	stat_segment_disconnect();
	return result;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	status_t status = FAILED;
	stat_segment_data_t *stats;
	sa_t *sa;
	counter_t bytes_total = 0, packets_total = 0;
	int i, j;

	DBG3(DBG_KNL, "querying SAD entry with SPI %.8x", ntohl(id->spi));

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);
	if (!sa)
	{
		DBG1(DBG_KNL, "required SA ID not found to query VPP");
		goto error;
	}

	stats = get_vpp_statistics(SA_STAT_SEGMENT_NAME);
	if (!stats)
	{
		DBG1(DBG_KNL, "unable to retrieve SA statistics from VPP");
		goto error;
	}

	for (i = 0; i < vec_len(stats); i++)
	{
		if (stats[i].type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED ||
			!stats[i].combined_counter_vec)
		{
			continue;
		}
		/* combine stats from all VPP threads */
		for (j = 0; j < vec_len(stats[i].combined_counter_vec); j++)
		{
			if (sa->stat_index <= vec_len(stats[i].combined_counter_vec[j]))
			{
				bytes_total += stats[i].combined_counter_vec[j][sa->stat_index].bytes;
				packets_total += stats[i].combined_counter_vec[j][sa->stat_index].packets;
			}
		}
	}
	stat_segment_data_free(stats);

	if (bytes)
	{
		*bytes = bytes_total;
	}
	if (packets)
	{
		*packets = packets_total;
	}
	if (time)
	{
		*time = 0;
	}
	status = SUCCESS;

error:
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	vapi_error_e rv;
	vapi_msg_ipsec_sad_entry_add_del_v2 *msg;
	vapi_payload_ipsec_sad_entry_add_del_v2_reply reply;
	sa_t *sa;

	DBG2(DBG_KNL, "deleting SAD entry with SPI %.8x", ntohl(id->spi));

	msg = vapi_alloc_ipsec_sad_entry_add_del_v2(this->vpp_ctx);

	this->mutex->lock(this->mutex);
	sa = this->sas->remove(this->sas, id);
	if (!sa)
	{
		DBG1(DBG_KNL, "unable to find SA entry with SPI %.8x", ntohl(id->spi));
		vapi_msg_free(this->vpp_ctx, msg);
		this->mutex->unlock(this->mutex);
		return NOT_FOUND;
	}
	this->mutex->unlock(this->mutex);

	msg->payload.is_add = FALSE;
	msg->payload.entry.sad_id = sa->sa_id;
	sa_destroy(sa);

	/* the code in VPP (ipsec_api.c) requires a number of the fields to be
	 * filled in, but it only cares about the sad_id when the deletion occurs */
	msg->payload.entry.spi = ntohl(id->spi);
	msg->payload.entry.protocol = map_protocol(id->proto);

	rv = vapi_ipsec_sad_entry_add_del_v2(this->vpp_ctx, msg, add_del_sad_cb,
										 &reply);
	if (rv != VAPI_OK || reply.retval)
	{
		DBG1(DBG_KNL, "unable to delete SAD entry with SPI %.8x (%d)",
			 ntohl(id->spi), rv ?: reply.retval);
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_vpp_ipsec_t *this)
{
	/* this is not being called by strongSwan anymore */
	return NOT_SUPPORTED;
}

/**
 * Callback for adding/deleting policies
 */
static vapi_error_e add_del_spd_entry_cb(vapi_ctx_t ctx, void *user,
										 vapi_error_e rv, bool is_last,
										 vapi_payload_ipsec_spd_entry_add_del_reply *p)
{
	vapi_payload_ipsec_spd_entry_add_del_reply *reply = user;

	if (p)
	{
		*reply = *p;
	}
	else
	{
		reply->retval = VNET_API_ERROR_RESPONSE_NOT_READY;
	}
	return VAPI_OK;
}

/*
 * Install/Delete a SPD Policy in vpp for use by a policy.
 */
static bool add_del_spd_entry(private_kernel_vpp_ipsec_t *this,
							  kernel_ipsec_policy_id_t *id,
							  kernel_ipsec_manage_policy_t *data, bool add)
{
	vapi_error_e rv;
	vapi_msg_ipsec_spd_entry_add_del *msg;
	vapi_type_ipsec_spd_entry *entry;
	vapi_payload_ipsec_spd_entry_add_del_reply reply;
	traffic_selector_t *local, *remote;
	uint32_t auto_priority;
	sa_t *sa;

	msg = vapi_alloc_ipsec_spd_entry_add_del(this->vpp_ctx);
	msg->payload.is_add = add;
	entry = &msg->payload.entry;
	entry->spd_id = this->spd_id;
	entry->is_outbound = (id->dir == POLICY_OUT);

	auto_priority = get_priority(id, data->prio);
	entry->priority = data->manual_prio ?: auto_priority;

	DBG2(DBG_KNL, "%s policy %R === %R %N [priority %u]",
		 add ? "adding" : "deleting", id->src_ts, id->dst_ts, policy_dir_names,
		 id->dir, entry->priority);

	switch (data->type)
	{
		case POLICY_IPSEC:
			/* when the policy is PROTECT, VPP must have a valid SA ID,
			 * trap policies/acquires are currently not supported */
			entry->policy = IPSEC_API_SPD_ACTION_PROTECT;
			if (data->sa)
			{
				kernel_ipsec_sa_id_t sa_id = {
					.src = data->src,
					.dst = data->dst,
					.proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
					.spi = (data->sa->esp.use ? data->sa->esp.spi :
												data->sa->ah.spi),
				};
				this->mutex->lock(this->mutex);
				sa = this->sas->get(this->sas, &sa_id);
				if (!sa)
				{
					this->mutex->unlock(this->mutex);
					DBG1(DBG_KNL, "required SA ID not found for policy, trap "
						 "policies are not supported by VPP");
					vapi_msg_free(this->vpp_ctx, msg);
					return FALSE;
				}
				entry->sa_id = sa->sa_id;
				this->mutex->unlock(this->mutex);
			}
			break;
		case POLICY_PASS:
			entry->policy = IPSEC_API_SPD_ACTION_BYPASS;
			break;
		case POLICY_DROP:
			entry->policy = IPSEC_API_SPD_ACTION_DISCARD;
			break;
	}

	/* src or dest proto may be "any" (0), use more restrictive one */
	entry->protocol = max(id->src_ts->get_protocol(id->src_ts),
						  id->dst_ts->get_protocol(id->dst_ts));
	if (id->dir == POLICY_OUT)
	{
		local = id->src_ts;
		remote = id->dst_ts;
	}
	else
	{
		remote = id->src_ts;
		local = id->dst_ts;
	}

	chunk_to_vapi_addr(local->get_from_address(local), &entry->local_address_start);
	chunk_to_vapi_addr(local->get_to_address(local), &entry->local_address_stop);
	chunk_to_vapi_addr(remote->get_from_address(remote), &entry->remote_address_start);
	chunk_to_vapi_addr(remote->get_to_address(remote), &entry->remote_address_stop);

	entry->local_port_start = local->get_from_port(local);
	entry->local_port_stop = local->get_to_port(local);
	entry->remote_port_start = remote->get_from_port(remote);
	entry->remote_port_stop = remote->get_to_port(remote);

	rv = vapi_ipsec_spd_entry_add_del(this->vpp_ctx, msg, add_del_spd_entry_cb,
									  &reply);
	if (rv != VAPI_OK || reply.retval)
	{
		DBG1(DBG_KNL, "unable to %s SPD entry (%d)", add ? "add" : "delete",
			 rv ?: reply.retval);
		return FALSE;
	}
	return TRUE;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	if (id->dir == POLICY_FWD)
	{
		/* forward policies are not supported by VPP */
		return SUCCESS;
	}
	if (!add_del_spd_entry(this, id, data, TRUE))
	{
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	/* policy stats from VPP use byte/packet counts */
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	if (id->dir == POLICY_FWD)
	{
		/* forward policies are not supported on VPP */
		return SUCCESS;
	}
	if (!add_del_spd_entry(this, id, data, FALSE))
	{
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_vpp_ipsec_t *this)
{
	/* this is not being called by strongSwan anymore */
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_vpp_ipsec_t *this, int fd, int family)
{
	/* FIXME: we may have to install port-specific bypass policies and/or maybe
	 * some punting rules?  */
	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_vpp_ipsec_t *this, int fd, int family, uint16_t port)
{
	/* FIXME: not sure if necessary on VPP */
	return TRUE;
}

/**
 * Callback for managing SPD in VPP that simply collects the return value
 */
static vapi_error_e manage_vpp_spd_cb(vapi_ctx_t ctx, void *user, vapi_error_e rv,
									  bool is_last,
									  vapi_payload_ipsec_spd_add_del_reply *p)
{
	*((uint32_t*)user) = p ? p->retval : VNET_API_ERROR_RESPONSE_NOT_READY;
	return VAPI_OK;
}

/**
 * Install or delete an SPD in VPP for use by policies.
 */
static bool manage_vpp_spd(private_kernel_vpp_ipsec_t *this, bool add,
						   uint32_t spd_id)
{
	vapi_error_e rv;
	uint32_t retval = 0;
	vapi_msg_ipsec_spd_add_del *msg;

	msg = vapi_alloc_ipsec_spd_add_del(this->vpp_ctx);
	msg->payload.is_add = add;
	msg->payload.spd_id = spd_id;

	rv = vapi_ipsec_spd_add_del(this->vpp_ctx, msg, manage_vpp_spd_cb, &retval);
	if (rv != VAPI_OK ||
		(retval &&  add && retval != VNET_API_ERROR_ENTRY_ALREADY_EXISTS) ||
		(retval && !add && retval != VNET_API_ERROR_NO_SUCH_ENTRY))
	{
		DBG1(DBG_KNL, "failed to %s VPP SPD with ID %d (%d)",
			 add ? "add" : "remove", spd_id, retval ?: rv);
		return FALSE;
	}
	else if (retval)
	{
		DBG2(DBG_KNL, "SPD with ID %d %s, ignored", spd_id,
			 add ? "to be added already exists" : "to be removed doesn't exist");
	}
	else
	{
		DBG2(DBG_KNL, "%s SPD with ID %d", add ? "added" : "removed",
			 spd_id);
	}
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_vpp_ipsec_t *this)
{
	this->mutex->destroy(this->mutex);
	this->sas->destroy(this->sas);
	DESTROY_IF(this->rng);

	if (this->vpp_ctx)
	{
		manage_vpp_spd(this, FALSE, this->spd_id);
		vapi_disconnect(this->vpp_ctx);
		vapi_ctx_free(this->vpp_ctx);
	}
	free(this);
}

/**
 * Callback that logs the VPP version
 */
static vapi_error_e log_version_cb(vapi_ctx_t ctx, void *user, vapi_error_e rv,
								   bool is_last, vapi_payload_show_version_reply *p)
{
	DBG2(DBG_KNL, "VPP (%s), version: %s, build date: %s", p->program,
		 p->version, p->build_date);
	return VAPI_OK;
}

/**
 * Initialize the VPP API
 */
static vapi_ctx_t vpp_api_init()
{
	vapi_ctx_t ctx = NULL;
	vapi_error_e rv;

	rv = vapi_ctx_alloc(&ctx);
	if (rv == VAPI_OK)
	{
		rv = vapi_connect(ctx,
				lib->settings->get_str(lib->settings,
					"%s.plugins.kernel-vpp.app_name",
					VPP_APP_NAME, lib->ns),
				lib->settings->get_str(lib->settings,
					"%s.plugins.kernel-vpp.api_prefix",
					NULL, lib->ns),
				lib->settings->get_int(lib->settings,
					"%s.plugins.kernel-vpp.max_outstanding_requests",
					VPP_MAX_OUTSTANDING_REQUESTS, lib->ns),
				lib->settings->get_int(lib->settings,
					"%s.plugins.kernel-vpp.response_queue_size",
					VPP_RESPONSE_QUEUE_SIZE, lib->ns),
				VAPI_MODE_BLOCKING, TRUE);

		if (rv == VAPI_OK)
		{
			vapi_msg_show_version *msg = vapi_alloc_show_version(ctx);
			vapi_show_version(ctx, msg, log_version_cb, NULL);
			return ctx;
		}
		else
		{
			DBG1(DBG_KNL, "unable to connect to VPP API (%d)", rv);
			vapi_ctx_free(ctx);
		}
	}
	else
	{
		DBG1(DBG_KNL, "unable to allocate VPP API context (%d)", rv);
	}
	return NULL;
}

/*
 * Described in header
 */
kernel_vpp_ipsec_t *kernel_vpp_ipsec_create()
{
	private_kernel_vpp_ipsec_t *this;

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
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.sas = hashtable_create((hashtable_hash_t)ipsec_sa_id_hash,
								(hashtable_equals_t)ipsec_sa_id_equals, 32),
		.vpp_ctx = vpp_api_init(),
		.spd_id = 1,
	);

	if (!this->vpp_ctx || !manage_vpp_spd(this, TRUE, this->spd_id))
	{
		destroy(this);
		return NULL;
	}

	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!this->rng)
	{
		DBG1(DBG_KNL, "failed to create RNG for SPI generation");
		destroy(this);
		return NULL;
	}
	return &this->public;
}
