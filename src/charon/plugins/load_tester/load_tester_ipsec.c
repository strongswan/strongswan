/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "load_tester_ipsec.h"

#include <time.h>

typedef struct private_load_tester_ipsec_t private_load_tester_ipsec_t;

/**
 * Private variables and functions of kernel_pfkey class.
 */
struct private_load_tester_ipsec_t {
	/**
	 * Public interface.
	 */
	load_tester_ipsec_t public;
	
	/**
	 * faked SPI counter
	 */
	u_int32_t spi;
};

/**
 * Implementation of kernel_interface_t.get_spi.
 */
static status_t get_spi(private_load_tester_ipsec_t *this, 
						host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid,
						u_int32_t *spi)
{
	*spi = ++this->spi;
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.get_cpi.
 */
static status_t get_cpi(private_load_tester_ipsec_t *this, 
						host_t *src, host_t *dst, 
						u_int32_t reqid, u_int16_t *cpi)
{
	return FAILED;
}

/**
 * Implementation of kernel_interface_t.add_sa.
 */
static status_t add_sa(private_load_tester_ipsec_t *this,
					   host_t *src, host_t *dst, u_int32_t spi,
					   protocol_id_t protocol, u_int32_t reqid,
					   u_int64_t expire_soft, u_int64_t expire_hard,
					   u_int16_t enc_alg, chunk_t enc_key,
					   u_int16_t int_alg, chunk_t int_key,
					   ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
					   bool encap, bool inbound)
{
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.update_sa.
 */
static status_t update_sa(private_load_tester_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol, u_int16_t cpi,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst,
						  bool encap, bool new_encap)
{
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.del_sa.
 */
static status_t del_sa(private_load_tester_ipsec_t *this, host_t *dst,
					   u_int32_t spi, protocol_id_t protocol, u_int16_t cpi)
{
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.add_policy.
 */
static status_t add_policy(private_load_tester_ipsec_t *this,
						   host_t *src, host_t *dst,
						   traffic_selector_t *src_ts,
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, u_int32_t spi,
						   protocol_id_t protocol, u_int32_t reqid,
						   ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
						   bool routed)
{
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.query_policy.
 */
static status_t query_policy(private_load_tester_ipsec_t *this,
							 traffic_selector_t *src_ts, 
							 traffic_selector_t *dst_ts,
							 policy_dir_t direction, u_int32_t *use_time)
{
	*use_time = time(NULL);
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.del_policy.
 */
static status_t del_policy(private_load_tester_ipsec_t *this,
						   traffic_selector_t *src_ts, 
						   traffic_selector_t *dst_ts,
						   policy_dir_t direction, bool unrouted)
{
	return SUCCESS;
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_load_tester_ipsec_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
load_tester_ipsec_t *load_tester_ipsec_create()
{
	private_load_tester_ipsec_t *this = malloc_thing(private_load_tester_ipsec_t);
	
	/* public functions */
	this->public.interface.get_spi = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.interface.get_cpi = (status_t(*)(kernel_ipsec_t*,host_t*,host_t*,u_int32_t,u_int16_t*))get_cpi;
	this->public.interface.add_sa  = (status_t(*)(kernel_ipsec_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,u_int16_t,chunk_t,u_int16_t,chunk_t,ipsec_mode_t,u_int16_t,u_int16_t,bool,bool))add_sa;
	this->public.interface.update_sa = (status_t(*)(kernel_ipsec_t*,u_int32_t,protocol_id_t,u_int16_t,host_t*,host_t*,host_t*,host_t*,bool,bool))update_sa;
	this->public.interface.del_sa = (status_t(*)(kernel_ipsec_t*,host_t*,u_int32_t,protocol_id_t,u_int16_t))del_sa;
	this->public.interface.add_policy = (status_t(*)(kernel_ipsec_t *this,host_t *, host_t *,traffic_selector_t *,traffic_selector_t *,policy_dir_t, u_int32_t,protocol_id_t, u_int32_t,ipsec_mode_t, u_int16_t, u_int16_t,bool))add_policy;
	this->public.interface.query_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.interface.del_policy = (status_t(*)(kernel_ipsec_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,bool))del_policy;
	this->public.interface.destroy = (void(*)(kernel_ipsec_t*)) destroy;
	
	this->spi = 0;
	
	return &this->public;
}

