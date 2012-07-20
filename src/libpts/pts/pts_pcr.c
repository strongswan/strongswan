/*
 * Copyright (C) 2012 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "pts_pcr.h"

#include <debug.h>

/**
 * Maximum number of PCR's of TPM, TPM Spec 1.2
 */
#define PCR_MAX_NUM				24

/**
 * Number of bytes that can be saved in a PCR of TPM, TPM Spec 1.2
 */
#define PCR_LEN					20

typedef struct private_pts_pcr_t private_pts_pcr_t;

/**
 * Private data of a pts_pcr_t object.
 *
 */
struct private_pts_pcr_t {

	/**
	 * Public pts_pcr_t interface.
	 */
	pts_pcr_t public;

	/**
	 * Shadow PCR registers
	 */
	chunk_t pcrs[PCR_MAX_NUM];

	/**
	 * Hasher used to extend shadow PCRs
	 */
	hasher_t *hasher;

};

METHOD(pts_pcr_t, get, chunk_t,
	private_pts_pcr_t *this, u_int32_t pcr)
{
	return (pcr < PCR_MAX_NUM) ? this->pcrs[pcr] : chunk_empty;
}

METHOD(pts_pcr_t, set, void,
	private_pts_pcr_t *this, u_int32_t pcr, chunk_t value)
{
	if (pcr < PCR_MAX_NUM && value.len == PCR_LEN)
	{
		memcpy(this->pcrs[pcr].ptr, value.ptr, PCR_LEN);
	}
}

METHOD(pts_pcr_t, extend, chunk_t,
	private_pts_pcr_t *this, u_int32_t pcr, chunk_t measurement)
{
	if (pcr >= PCR_MAX_NUM || measurement.len != PCR_LEN)
	{
		DBG1(DBG_PTS, "PCR%d does not exist or has the wrong size", pcr);
		return chunk_empty;
	}
	if (!this->hasher->get_hash(this->hasher, this->pcrs[pcr] , NULL) ||
		!this->hasher->get_hash(this->hasher, measurement, this->pcrs[pcr].ptr))
	{
		DBG1(DBG_PTS, "PCR%d was not extended due to a hasher problem", pcr);
		return chunk_empty;
	}
	return this->pcrs[pcr];
}

METHOD(pts_pcr_t, destroy, void,
	private_pts_pcr_t *this)
{
	u_int32_t i;

	for (i = 0; i < PCR_MAX_NUM; i++)
	{
		free(this->pcrs[i].ptr);
	}
	this->hasher->destroy(this->hasher);
	free(this);
}

/**
 * See header
 */
pts_pcr_t *pts_pcr_create(void)
{
	private_pts_pcr_t *this;
	hasher_t *hasher;
	u_int32_t i;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1(DBG_PTS, "%N hasher could not be created",
			 hash_algorithm_short_names, HASH_SHA1);
		return NULL;
	}

	INIT(this,
		.public = {
			.get = _get,
			.set = _set,
			.extend = _extend,
			.destroy = _destroy,
		},
		.hasher = hasher,
	);

	for (i = 0; i < PCR_MAX_NUM; i++)
	{
		this->pcrs[i] = chunk_alloc(PCR_LEN);
		memset(this->pcrs[i].ptr, 0x00, PCR_LEN);
	}

	return &this->public;
}

