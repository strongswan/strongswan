/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

#include "ipsec_sa.h"

#include <library.h>
#include <utils/debug.h>

typedef struct private_ipsec_sa_t private_ipsec_sa_t;

/**
 * Private additions to ipsec_sa_t.
 */
struct private_ipsec_sa_t {

	/**
	 * Public members
	 */
	ipsec_sa_t public;

	/**
	 * SPI of this SA
	 */
	u_int32_t spi;

	/**
	 * Source address
	 */
	host_t *src;

	/**
	 * Destination address
	 */
	host_t *dst;

	/**
	 * Protocol
	 */
	u_int8_t protocol;

	/**
	 * Reqid of this SA
	 */
	u_int32_t reqid;

	/**
	 * Lifetime configuration
	 */
	lifetime_cfg_t lifetime;

	/**
	 * IPsec mode
	 */
	ipsec_mode_t mode;

	/**
	 * TRUE if extended sequence numbers are used
	 */
	bool esn;

	/**
	 * TRUE if this is an inbound SA
	 */
	bool inbound;

	/**
	 * ESP context
	 */
	esp_context_t *esp_context;
};

METHOD(ipsec_sa_t, get_source, host_t*,
	private_ipsec_sa_t *this)
{
	return this->src;
}

METHOD(ipsec_sa_t, get_destination, host_t*,
	private_ipsec_sa_t *this)
{
	return this->dst;
}

METHOD(ipsec_sa_t, set_source, void,
	private_ipsec_sa_t *this, host_t *addr)
{
	this->src->destroy(this->src);
	this->src = addr->clone(addr);
}

METHOD(ipsec_sa_t, set_destination, void,
	private_ipsec_sa_t *this, host_t *addr)
{
	this->dst->destroy(this->dst);
	this->dst = addr->clone(addr);
}

METHOD(ipsec_sa_t, get_spi, u_int32_t,
	private_ipsec_sa_t *this)
{
	return this->spi;
}

METHOD(ipsec_sa_t, get_reqid, u_int32_t,
	private_ipsec_sa_t *this)
{
	return this->reqid;
}

METHOD(ipsec_sa_t, get_protocol, u_int8_t,
	private_ipsec_sa_t *this)
{
	return this->protocol;
}

METHOD(ipsec_sa_t, get_lifetime, lifetime_cfg_t*,
	private_ipsec_sa_t *this)
{
	return &this->lifetime;
}

METHOD(ipsec_sa_t, is_inbound, bool,
	private_ipsec_sa_t *this)
{
	return this->inbound;
}

METHOD(ipsec_sa_t, get_esp_context, esp_context_t*,
	private_ipsec_sa_t *this)
{
	return this->esp_context;
}

METHOD(ipsec_sa_t, match_by_spi_dst, bool,
	private_ipsec_sa_t *this, u_int32_t spi, host_t *dst)
{
	return this->spi == spi && this->dst->ip_equals(this->dst, dst);
}

METHOD(ipsec_sa_t, match_by_spi_src_dst, bool,
	private_ipsec_sa_t *this, u_int32_t spi, host_t *src, host_t *dst)
{
	return this->spi == spi && this->src->ip_equals(this->src, src) &&
		   this->dst->ip_equals(this->dst, dst);
}

METHOD(ipsec_sa_t, match_by_reqid, bool,
	private_ipsec_sa_t *this, u_int32_t reqid, bool inbound)
{
	return this->reqid == reqid && this->inbound == inbound;
}

METHOD(ipsec_sa_t, destroy, void,
	private_ipsec_sa_t *this)
{
	this->src->destroy(this->src);
	this->dst->destroy(this->dst);
	DESTROY_IF(this->esp_context);
	free(this);
}

/**
 * Described in header.
 */
ipsec_sa_t *ipsec_sa_create(u_int32_t spi, host_t *src, host_t *dst,
		u_int8_t protocol, u_int32_t reqid, mark_t mark, u_int32_t tfc,
		lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
		u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode,
		u_int16_t ipcomp, u_int16_t cpi, bool encap, bool esn, bool inbound,
		traffic_selector_t *src_ts,	traffic_selector_t *dst_ts)
{
	private_ipsec_sa_t *this;

	if (protocol != IPPROTO_ESP)
	{
		DBG1(DBG_ESP, "  IPsec SA: protocol not supported");
		return NULL;
	}
	if (!encap)
	{
		DBG1(DBG_ESP, "  IPsec SA: only UDP encapsulation is supported");
		return NULL;
	}
	if (esn)
	{
		DBG1(DBG_ESP, "  IPsec SA: ESN not supported");
		return NULL;
	}
	if (ipcomp != IPCOMP_NONE)
	{
		DBG1(DBG_ESP, "  IPsec SA: compression not supported");
		return NULL;
	}
	if (mode != MODE_TUNNEL)
	{
		DBG1(DBG_ESP, "  IPsec SA: unsupported mode");
		return NULL;
	}

	INIT(this,
		.public = {
			.destroy = _destroy,
			.get_source = _get_source,
			.get_destination = _get_destination,
			.set_source = _set_source,
			.set_destination = _set_destination,
			.get_spi = _get_spi,
			.get_reqid = _get_reqid,
			.get_protocol = _get_protocol,
			.get_lifetime = _get_lifetime,
			.is_inbound = _is_inbound,
			.match_by_spi_dst = _match_by_spi_dst,
			.match_by_spi_src_dst = _match_by_spi_src_dst,
			.match_by_reqid = _match_by_reqid,
			.get_esp_context = _get_esp_context,
		},
		.spi = spi,
		.src = src->clone(src),
		.dst = dst->clone(dst),
		.lifetime = *lifetime,
		.protocol = protocol,
		.reqid = reqid,
		.mode = mode,
		.esn = esn,
		.inbound = inbound,
	);

	this->esp_context = esp_context_create(enc_alg, enc_key, int_alg, int_key,
										   inbound);
	if (!this->esp_context)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}
