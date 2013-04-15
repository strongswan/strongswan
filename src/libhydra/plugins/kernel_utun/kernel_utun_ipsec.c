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

#include "kernel_utun_ipsec.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/if_utun_crypto.h>
#include <net/if_utun_crypto_ipsec.h>
#include <netinet/in_var.h>
#include <sys/kern_control.h>

#include <hydra.h>
#include <utils/debug.h>
#include <threading/mutex.h>
#include <networking/tun_device.h>

typedef struct private_kernel_utun_ipsec_t private_kernel_utun_ipsec_t;

/**
 * Private variables and functions of kernel_utun class.
 */
struct private_kernel_utun_ipsec_t {

	/**
	 * Public part of the kernel_utun_t object
	 */
	kernel_utun_ipsec_t public;

	/**
	 * Mutex to access shared objects
	 */
	mutex_t *mutex;

	/**
	 * List of tun devices, as tun_device_t
	 */
	linked_list_t *tuns;
};

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_utun_ipsec_t *this)
{
	return 0;
}

/**
 * Enable IPsec crypt extension on utun device
 */
static bool enable_crypto(tun_device_t *tun)
{
	utun_crypto_args_t args = {
		.ver = UTUN_CRYPTO_VER_1,
		.type = UTUN_CRYPTO_TYPE_IPSEC,
		.args_ulen = sizeof(utun_crypto_ipsec_args_v1_t),
		.u = {
			.ipsec_v1 = {
				/* nothing to set */
			},
		},
	};
	if (setsockopt(tun->get_fd(tun), SYSPROTO_CONTROL, UTUN_OPT_ENABLE_CRYPTO,
				   &args, sizeof(args)) < 0)
	{
		DBG1(DBG_KNL, "enabling crypto on %s failed: %s",
			 tun->get_name(tun), strerror(errno));
		return FALSE;
	}
	if (setsockopt(tun->get_fd(tun), SYSPROTO_CONTROL,
				   UTUN_OPT_START_CRYPTO_DATA_TRAFFIC, &args, sizeof(args)) < 0)
	{
		DBG1(DBG_KNL, "starting crypto traffic on %s failed: %s",
			 tun->get_name(tun), strerror(errno));
		return FALSE;
	}
	return TRUE;
}

/**
 * Allocate an SPI on the given tun device
 */
static bool alloc_spi(tun_device_t *tun, host_t *src, host_t *dst,
					  u_int32_t reqid, u_int32_t *spi)
{
	utun_crypto_keys_idx_args_t args = {
		.ver = UTUN_CRYPTO_VER_1,
		.type = UTUN_CRYPTO_TYPE_IPSEC,
		.dir = UTUN_CRYPTO_DIR_IN,
		.args_ulen = sizeof(utun_crypto_keys_idx_ipsec_args_v1_t),
		.u = {
			.ipsec_v1 = {
				.proto = IF_UTUN_CRYPTO_IPSEC_PROTO_ESP,
				.mode = IF_UTUN_CRYPTO_IPSEC_MODE_TUNNEL,
				.reqid = reqid,
				.spirange_min = 0xd0000000,
				.spirange_max = 0xdfffffff,
			},
		},
	};
	socklen_t len;

	len = sizeof(args);
	if (getsockopt(tun->get_fd(tun), SYSPROTO_CONTROL,
				   UTUN_OPT_GENERATE_CRYPTO_KEYS_IDX, &args, &len) < 0 ||
		len != sizeof(args))
	{
		DBG1(DBG_KNL, "allocating SPI on %s failed: %s",
			 tun->get_name(tun), strerror(errno));
		return FALSE;
	}
	*spi = htonl(args.u.ipsec_v1.spi);
	return TRUE;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	tun_device_t *tun;

	if (protocol != IPPROTO_ESP)
	{
		return NOT_SUPPORTED;
	}
	tun = tun_device_create(NULL);
	if (!tun)
	{
		return FAILED;
	}
	if (!enable_crypto(tun) || !alloc_spi(tun, src, dst, reqid, spi))
	{
		tun->destroy(tun);
		return FAILED;
	}

	this->mutex->lock(this->mutex);
	this->tuns->insert_last(this->tuns, tun);
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return FAILED;
}

/**
 * Integrity IKEv2 identifiers => utun identifiers
 */
static struct {
	integrity_algorithm_t alg;
	if_utun_crypto_ipsec_auth_t utun;
} int_alg_map[] = {
	{ AUTH_HMAC_MD5_96,				IF_UTUN_CRYPTO_IPSEC_AUTH_MD5			},
	{ AUTH_HMAC_SHA1_96,			IF_UTUN_CRYPTO_IPSEC_AUTH_SHA1			},
	{ AUTH_HMAC_SHA2_256_128,		IF_UTUN_CRYPTO_IPSEC_AUTH_SHA256		},
	{ AUTH_HMAC_SHA2_384_192,		IF_UTUN_CRYPTO_IPSEC_AUTH_SHA384		},
	{ AUTH_HMAC_SHA2_512_256,		IF_UTUN_CRYPTO_IPSEC_AUTH_SHA512		},
};

/**
 * Mapping function for integrity algs
 */
static if_utun_crypto_ipsec_auth_t map_int_alg(integrity_algorithm_t alg)
{
	int i;

	for (i = 0; i < countof(int_alg_map); i++)
	{
		if (int_alg_map[i].alg == alg)
		{
			return int_alg_map[i].utun;
		}
	}
	return IF_UTUN_CRYPTO_IPSEC_AUTH_NONE;
}

/**
 * Encryption IKEv2 identifiers => utun identifiers
 */
static struct {
	encryption_algorithm_t alg;
	int key_size;
	if_utun_crypto_ipsec_enc_t utun;
} enc_alg_map[] = {
	{ ENCR_DES,					 0,	IF_UTUN_CRYPTO_IPSEC_ENC_DES			},
	{ ENCR_3DES,				 0,	IF_UTUN_CRYPTO_IPSEC_ENC_3DES			},
	{ ENCR_AES_CBC,				16,	IF_UTUN_CRYPTO_IPSEC_ENC_AES128			},
	{ ENCR_AES_CBC,				32,	IF_UTUN_CRYPTO_IPSEC_ENC_AES256			},
};

/**
 * Mapping function for encryption algs
 */
static if_utun_crypto_ipsec_enc_t map_enc_alg(encryption_algorithm_t alg,
											  int key_size)
{
	int i;

	for (i = 0; i < countof(int_alg_map); i++)
	{
		if (enc_alg_map[i].alg == alg)
		{
			if (enc_alg_map[i].key_size == 0 ||
				enc_alg_map[i].key_size == key_size)
			{
				return enc_alg_map[i].utun;
			}
		}
	}
	return IF_UTUN_CRYPTO_IPSEC_ENC_NONE;
}

/**
 * Install an SA to a crypto-enabled utun device
 */
static status_t add_sa_tun(private_kernel_utun_ipsec_t *this, tun_device_t *tun,
	host_t *src, host_t *dst, u_int32_t spi, u_int32_t reqid,
	u_int16_t enc_alg, chunk_t enc_key, u_int16_t int_alg, chunk_t int_key,
	bool encap, bool inbound, u_int64_t hard, u_int64_t soft)
{
	struct __attribute__((__packed__)){
		utun_crypto_keys_args_t args;
		u_int8_t auth[int_key.len];
		u_int8_t enc[enc_key.len];
	} keys;

	keys.args = (utun_crypto_keys_args_t) {
		.ver = UTUN_CRYPTO_VER_1,
		.type = UTUN_CRYPTO_TYPE_IPSEC,
		.dir = inbound ? UTUN_CRYPTO_DIR_IN : UTUN_CRYPTO_DIR_OUT,
		.args_ulen = sizeof(utun_crypto_keys_ipsec_args_v1_t),
		.varargs_buflen = int_key.len + enc_key.len,
		.u = {
			.ipsec_v1 = {
				.proto = IF_UTUN_CRYPTO_IPSEC_PROTO_ESP,
				.mode = IF_UTUN_CRYPTO_IPSEC_MODE_TUNNEL,
				.alg_auth = map_int_alg(int_alg),
				.alg_enc = map_enc_alg(enc_alg, enc_key.len),
				.keepalive = IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_NONE,
				.natd = IF_UTUN_CRYPTO_IPSEC_NATD_NONE,
				.replay = 32,
				.key_auth_len = int_key.len * 8,
				.key_enc_len = enc_key.len * 8,
				.spi = ntohl(spi),
				.pid = getpid(),
				.reqid = reqid,
				.lifetime_hard = hard,
				.lifetime_soft = soft,
			},
		},
	};

	if (keys.args.u.ipsec_v1.alg_auth == IF_UTUN_CRYPTO_IPSEC_AUTH_NONE)
	{
		DBG1(DBG_KNL, "%N integrity not supported by utun",
			 integrity_algorithm_names, int_alg);
		return NOT_SUPPORTED;
	}
	if (keys.args.u.ipsec_v1.alg_enc == IF_UTUN_CRYPTO_IPSEC_ENC_NONE)
	{
		DBG1(DBG_KNL, "%N encryption not supported by utun",
			 encryption_algorithm_names, enc_alg);
		return NOT_SUPPORTED;
	}

	if (encap)
	{
		keys.args.u.ipsec_v1.natd = IF_UTUN_CRYPTO_IPSEC_NATD_MINE;
		keys.args.u.ipsec_v1.keepalive = IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_NATT;
	}
	memcpy(keys.auth, int_key.ptr, int_key.len);
	memcpy(keys.enc, enc_key.ptr, enc_key.len);
	memcpy(&keys.args.u.ipsec_v1.src_addr,
		   src->get_sockaddr(src), *src->get_sockaddr_len(src));
	memcpy(&keys.args.u.ipsec_v1.dst_addr,
		   dst->get_sockaddr(dst), *dst->get_sockaddr_len(dst));

	if (setsockopt(tun->get_fd(tun), SYSPROTO_CONTROL,
				   UTUN_OPT_CONFIG_CRYPTO_KEYS, &keys, sizeof(keys)) < 0)
	{
		DBG1(DBG_KNL, "adding SA to %s failed: %s",
			 tun->get_name(tun), strerror(errno));
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t* src_ts, traffic_selector_t* dst_ts)
{
	enumerator_t *enumerator;
	tun_device_t *tun;
	traffic_selector_t *ts;
	status_t status = NOT_FOUND;
	host_t *host;

	if (protocol != IPPROTO_ESP || mode != MODE_TUNNEL || esn)
	{
		return NOT_SUPPORTED;
	}

	ts = inbound ? dst_ts : src_ts;
	this->mutex->lock(this->mutex);
	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, &tun))
	{
		host = tun->get_address(tun, NULL);
		if (host && ts->includes(ts, host))
		{
			status = add_sa_tun(this, tun, src, dst, spi, reqid,
							enc_alg, enc_key, int_alg, int_key, encap, inbound,
							lifetime->time.life, lifetime->time.rekey);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark,
	u_int64_t *bytes, u_int64_t *packets)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_utun_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool old_encap, bool new_encap, mark_t mark)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_utun_ipsec_t *this)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_utun_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	u_int32_t *use_time)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_utun_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t prio)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_utun_ipsec_t *this)
{
	return FAILED;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_utun_ipsec_t *this, int fd, int family)
{
	return FALSE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_utun_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return FALSE;
}

METHOD(kernel_utun_ipsec_t, add_ip, status_t,
	private_kernel_utun_ipsec_t *this, host_t *vip, int prefix)
{
	tun_device_t *tun;
	bool added = FALSE;

	if (prefix == -1)
	{
		switch (vip->get_family(vip))
		{
			case AF_INET:
				prefix = 32;
				break;
			case AF_INET6:
				prefix = 128;
				break;
			default:
				return NOT_SUPPORTED;
		}
	}
	this->mutex->lock(this->mutex);
	if (this->tuns->get_last(this->tuns, (void**)&tun) == SUCCESS)
	{
		added = tun->set_address(tun, vip, prefix) &&
				tun->set_mtu(tun, 1280) &&
				tun->up(tun);
	}
	this->mutex->unlock(this->mutex);

	if (added)
	{
		return SUCCESS;
	}
	return FAILED;
}

METHOD(kernel_utun_ipsec_t, del_ip, status_t,
	private_kernel_utun_ipsec_t *this, host_t *vip, int prefix)
{
	enumerator_t *enumerator;
	tun_device_t *tun;
	host_t *host;
	bool found;

	this->mutex->lock(this->mutex);
	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, &tun))
	{
		host = tun->get_address(tun, NULL);
		if (host && host->ip_equals(host, vip))
		{
			this->tuns->remove_at(this->tuns, enumerator);
			tun->destroy(tun);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (found)
	{
		return SUCCESS;
	}
	return NOT_FOUND;
}

/**
 * Globally referencable instance of kernek_utun_ipsec instance
 */
static kernel_utun_ipsec_t *singleton;

/**
 * See header.
 */
kernel_utun_ipsec_t *kernel_utun_ipsec_get()
{
	return singleton;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_utun_ipsec_t *this)
{
	singleton = NULL;
	this->tuns->destroy_offset(this->tuns, offsetof(tun_device_t, destroy));
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_utun_ipsec_t *kernel_utun_ipsec_create()
{
	private_kernel_utun_ipsec_t *this;

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
			.add_ip = _add_ip,
			.del_ip = _del_ip,
		},
		.tuns = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);
	singleton = &this->public;
	return &this->public;
}
