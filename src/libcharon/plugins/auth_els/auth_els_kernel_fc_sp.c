/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "auth_els_kernel_fc_sp.h"

#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <processing/jobs/delete_ike_sa_job.h>
#include <threading/rwlock.h>
#include <threading/mutex.h>
#include <daemon.h>

#include "auth_els_utils.h"

#include <errno.h>
#include <linux/xfrm.h>
#include <utils/debug.h>
#include <utils/chunk.h>

typedef struct private_auth_els_kernel_fc_sp_t private_auth_els_kernel_fc_sp_t;

/**
 * Private variables and functions of auth_els kernel ipsec instance.
 */
struct private_auth_els_kernel_fc_sp_t {

	/**
	 * Public auth_els_kernel_ipsec interface.
	 */
	auth_els_kernel_fc_sp_t public;

	/**
	 * RNG used for SPI generation.
	 */
	rng_t *rng;
	/**
	 * Lock to access the RNG instance and the callback for getting spi
	 */
	rwlock_t *spi_lock;
};


METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_auth_els_kernel_fc_sp_t *this)
{
	DBG2 (DBG_CFG, "auth_els - auth_els_kernel_ipsec - get_features callback, ignoring");
	return KERNEL_POLICY_SPI;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_auth_els_kernel_fc_sp_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	DBG_ENTER;
	
	bool result = FALSE;

	this->spi_lock->read_lock(this->spi_lock);

	if (!this->rng)
	{
		DBG_FATAL ("unable to create RNG");
		*spi = 0;
		this->spi_lock->unlock(this->spi_lock);
		return FAILED;
	}

	result = this->rng->get_bytes(this->rng, sizeof(uint32_t),
								  (uint8_t *)spi);
	if (!result)
	{
		DBG_FATAL ("get_spi failed, set to 0");
		*spi = 0;
	}
	this->spi_lock->unlock(this->spi_lock);

	DBG_STD ("src port_number %d dest port_number %d, spi provided: %x", src->get_port(src), dst->get_port(dst), *spi);

	return result ? SUCCESS : FAILED;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_auth_els_kernel_fc_sp_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	DBG_ENTER;
	(void) this;
	(void) src;
	(void) dst;
	(void) cpi;
	
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	DBG_ENTER;

	uint32_t key_size;
	uint16_t remote_port_number;
	status_t final_status = FAILED;

	key_size = data->enc_key.len - 4;

	if (data->inbound)
	{
		remote_port_number = id->src->get_port(id->src);
	}
	else
	{
		remote_port_number = id->dst->get_port(id->dst);
	}
	
	DBG_STD ("remote_port_number: %d, enc_alg: %N, key_size: %d", 
				remote_port_number, encryption_algorithm_names, data->enc_alg, key_size);
	
	return final_status;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	DBG_ENTER;
	
	int ret_status = SUCCESS;
	
	*bytes = 0;
	*packets = 0;		// Driver only provides bytes for now.
	
	return ret_status;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
		private_auth_els_kernel_fc_sp_t *this,
		kernel_ipsec_sa_id_t *id,
		kernel_ipsec_del_sa_t *data) 
{
	status_t final_status = FAILED;
	
	DBG_STD ("start: spi: %x", id->spi);
	
	return final_status;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	DBG_ENTER;
	DBG_STD ("child_sa: me: %d, other: %d", 
				id->src->get_port(id->src), id->dst->get_port(id->dst));
	
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_auth_els_kernel_fc_sp_t *this)
{
	DBG_ENTER;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	DBG_ENTER;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	DBG_ENTER;
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_auth_els_kernel_fc_sp_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	DBG_ENTER;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_auth_els_kernel_fc_sp_t *this)
{
	DBG_ENTER;
	return SUCCESS;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_auth_els_kernel_fc_sp_t *this, int fd, int family)
{
	DBG_ENTER;
	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_auth_els_kernel_fc_sp_t *this, int fd, int family, uint16_t port)
{
	DBG_ENTER;
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_auth_els_kernel_fc_sp_t *this)
{
	DESTROY_IF(this->rng);
	DESTROY_IF(this->spi_lock);
	free(this);
}

/*
 * Described in header.
 */
auth_els_kernel_fc_sp_t *auth_els_kernel_fc_sp_create()
{
	private_auth_els_kernel_fc_sp_t *this;

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
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		.spi_lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
