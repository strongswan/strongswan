/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
 * Hochschule fuer Technik Rapperswil
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

#include <errno.h>
#include <netinet/udp.h>
#include <linux/xfrm.h>
#include <utils/debug.h>
#include <utils/chunk.h>
#include <tkm/constants.h>
#include <tkm/client.h>

#include "tkm.h"
#include "tkm_types.h"
#include "tkm_keymat.h"
#include "tkm_kernel_sad.h"
#include "tkm_kernel_ipsec.h"

typedef struct private_tkm_kernel_ipsec_t private_tkm_kernel_ipsec_t;

/**
 * Private variables and functions of TKM kernel ipsec instance.
 */
struct private_tkm_kernel_ipsec_t {

	/**
	 * Public tkm_kernel_ipsec interface.
	 */
	tkm_kernel_ipsec_t public;

	/**
	 * RNG used for SPI generation.
	 */
	rng_t *rng;

	/**
	 * CHILD/ESP SA database.
	 */
	tkm_kernel_sad_t *sad;

};

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	DBG1(DBG_KNL, "getting SPI for reqid {%u}", reqid);
	const bool result = this->rng->get_bytes(this->rng, sizeof(u_int32_t),
											 (u_int8_t *)spi);
	return result ? SUCCESS : FAILED;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t* src_ts, traffic_selector_t* dst_ts)
{
	if (!inbound)
	{
		return SUCCESS;
	}
	const esa_info_t esa = *(esa_info_t *)(enc_key.ptr);
	const esa_id_type esa_id = tkm->idmgr->acquire_id(tkm->idmgr, TKM_CTX_ESA);
	DBG1(DBG_KNL, "adding child SA (esa: %llu, isa: %llu, esp_spi_loc: %x, "
		 "esp_spi_rem: %x)", esa_id, esa.isa_id, ntohl(spi), ntohl(esa.spi_r));
	if (!this->sad->insert(this->sad, esa_id, src, dst, spi, protocol))
	{
		DBG1(DBG_KNL, "unable to add entry (%llu) to SAD", esa_id);
		tkm->idmgr->release_id(tkm->idmgr, TKM_CTX_ESA, esa_id);
		return FAILED;
	}
	if (ike_esa_create_first(esa_id, esa.isa_id, 1, 1, ntohl(spi),
							 ntohl(esa.spi_r)) != TKM_OK)
	{
		DBG1(DBG_KNL, "child SA (%llu) creation failed", esa_id);
		this->sad->remove(this->sad, esa_id);
		tkm->idmgr->release_id(tkm->idmgr, TKM_CTX_ESA, esa_id);
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes,
	u_int64_t *packets)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	const esa_id_type esa_id = this->sad->get_esa_id(this->sad, src, dst, spi,
													 protocol);
	if (esa_id)
	{
		DBG1(DBG_KNL, "deleting child SA (esa: %llu, spi: %x)", esa_id,
			 ntohl(spi));
		if (ike_esa_reset(esa_id) != TKM_OK)
		{
			DBG1(DBG_KNL, "child SA (%llu) deletion failed", esa_id);
			return FAILED;
		}
		this->sad->remove(this->sad, esa_id);
		tkm->idmgr->release_id(tkm->idmgr, TKM_CTX_ESA, esa_id);
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_tkm_kernel_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool old_encap, bool new_encap, mark_t mark)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_tkm_kernel_ipsec_t *this)
{
	DBG1(DBG_KNL, "flushing child SA entries");
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_tkm_kernel_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	u_int32_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_tkm_kernel_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t prio)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_tkm_kernel_ipsec_t *this)
{
	return SUCCESS;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_tkm_kernel_ipsec_t *this, int fd, int family)
{
	struct xfrm_userpolicy_info policy;
	u_int sol, ipsec_policy;

	switch (family)
	{
		case AF_INET:
			sol = SOL_IP;
			ipsec_policy = IP_XFRM_POLICY;
			break;
		case AF_INET6:
			sol = SOL_IPV6;
			ipsec_policy = IPV6_XFRM_POLICY;
			break;
		default:
			return FALSE;
	}

	memset(&policy, 0, sizeof(policy));
	policy.action = XFRM_POLICY_ALLOW;
	policy.sel.family = family;

	policy.dir = XFRM_POLICY_OUT;
	if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s",
					   strerror(errno));
		return FALSE;
	}
	policy.dir = XFRM_POLICY_IN;
	if (setsockopt(fd, sol, ipsec_policy, &policy, sizeof(policy)) < 0)
	{
		DBG1(DBG_KNL, "unable to set IPSEC_POLICY on socket: %s",
					   strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_tkm_kernel_ipsec_t *this, int fd, int family, u_int16_t port)
{
	int type = UDP_ENCAP_ESPINUDP;

	if (setsockopt(fd, SOL_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
	{
		DBG1(DBG_KNL, "unable to set UDP_ENCAP: %s", strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_tkm_kernel_ipsec_t *this)
{
	DESTROY_IF(this->rng);
	DESTROY_IF(this->sad);
	free(this);
}

/*
 * Described in header.
 */
tkm_kernel_ipsec_t *tkm_kernel_ipsec_create()
{
	private_tkm_kernel_ipsec_t *this;

	INIT(this,
		.public = {
			.interface = {
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
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		.sad = tkm_kernel_sad_create(),
	);

	if (!this->rng)
	{
		DBG1(DBG_KNL, "unable to create RNG");
		destroy(this);
		return NULL;
	}
	if (!this->sad)
	{
		DBG1(DBG_KNL, "unable to create SAD");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
