/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include "pts.h"

#include <debug.h>
#include <crypto/hashers/hasher.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

typedef struct private_pts_t private_pts_t;

/**
 * Private data of a pts_t object.
 *
 */
struct private_pts_t {

	/**
	 * Public pts_t interface.
	 */
	pts_t public;

	/**
	 * PTS Protocol Capabilities
	 */
	pts_proto_caps_flag_t proto_caps;

	/**
	 * PTS Measurement Algorithm
	 */
	pts_meas_algorithms_t algorithm;

	/**
	 * Do we have an activated TPM
	 */
	bool has_tpm;

	/**
	 * Contains a TPM_CAP_VERSION_INFO struct
	 */
	chunk_t tpm_version_info;
};

METHOD(pts_t, get_proto_caps, pts_proto_caps_flag_t,
	private_pts_t *this)
{
	return this->proto_caps;
}

METHOD(pts_t, set_proto_caps, void,
	private_pts_t *this, pts_proto_caps_flag_t flags)
{
	this->proto_caps = flags;
	DBG2(DBG_TNC, "supported PTS protocol capabilities: %s%s%s%s%s",
				   flags & PTS_PROTO_CAPS_C ? "C" : ".",
				   flags & PTS_PROTO_CAPS_V ? "V" : ".",
				   flags & PTS_PROTO_CAPS_D ? "D" : ".",
				   flags & PTS_PROTO_CAPS_T ? "T" : ".",
				   flags & PTS_PROTO_CAPS_X ? "X" : ".");
}

METHOD(pts_t, get_meas_algorithm, pts_meas_algorithms_t,
	private_pts_t *this)
{
	return this->algorithm;
}

METHOD(pts_t, set_meas_algorithm, void,
	private_pts_t *this, pts_meas_algorithms_t algorithm)
{
	hash_algorithm_t hash_alg;

	hash_alg = pts_meas_to_hash_algorithm(algorithm);
	DBG2(DBG_TNC, "selected PTS measurement algorithm is %N",
				   hash_algorithm_names, hash_alg);
	if (hash_alg != HASH_UNKNOWN)
	{
		this->algorithm = algorithm;
	}
}

/**
 * Print TPM 1.2 Version Info
 */
static void print_tpm_version_info(private_pts_t *this)
{
	TPM_CAP_VERSION_INFO versionInfo;
	UINT64 offset = 0;
	TSS_RESULT result;

	result = Trspi_UnloadBlob_CAP_VERSION_INFO(&offset,
						 	this->tpm_version_info.ptr, &versionInfo);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_TNC, "could not parse tpm version info: tss error 0x%x",
			 result);
	}
	else
	{
		DBG2(DBG_TNC, "TPM 1.2 Version Info: Chip Version: %hhu.%hhu.%hhu.%hhu,"
			 " Spec Level: %hu, Errata Rev: %hhu, Vendor ID: %.4s",
			 versionInfo.version.major, versionInfo.version.minor,
			 versionInfo.version.revMajor, versionInfo.version.revMinor,
			 versionInfo.specLevel, versionInfo.errataRev, 
			 versionInfo.tpmVendorID);
	}
}

METHOD(pts_t, get_tpm_version_info, bool,
	private_pts_t *this, chunk_t *info)
{
	if (!this->has_tpm)
	{
		return FALSE;
	}
	*info = this->tpm_version_info;
	print_tpm_version_info(this);
	return TRUE;
}

METHOD(pts_t, set_tpm_version_info, void,
	private_pts_t *this, chunk_t info)
{
	this->tpm_version_info = chunk_clone(info);
	print_tpm_version_info(this);
}

METHOD(pts_t, destroy, void,
	private_pts_t *this)
{
	free(this->tpm_version_info.ptr);
	free(this);
}

/**
 * Check for a TPM by querying for TPM Version Info
 */
static bool has_tpm(private_pts_t *this)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_VERSION_VAL,  0, NULL,
									&this->tpm_version_info.len,
									&this->tpm_version_info.ptr);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	this->tpm_version_info = chunk_clone(this->tpm_version_info);
	return TRUE;

err:
	DBG1(DBG_TNC, "TPM not available: tss error 0x%x", result);
	return FALSE;
}

/**
 * See header
 */
pts_t *pts_create(bool is_imc)
{
	private_pts_t *this;

	INIT(this,
		.public = {
			.get_proto_caps = _get_proto_caps,
			.set_proto_caps = _set_proto_caps,
			.get_meas_algorithm = _get_meas_algorithm,
			.set_meas_algorithm = _set_meas_algorithm,
			.get_tpm_version_info = _get_tpm_version_info,
			.set_tpm_version_info = _set_tpm_version_info,
			.destroy = _destroy,
		},
		.proto_caps = PTS_PROTO_CAPS_V,
		.algorithm = PTS_MEAS_ALGO_SHA256,
	);

	if (is_imc)
	{
		if (has_tpm(this))
		{
			this->has_tpm = TRUE;
			this->proto_caps |= PTS_PROTO_CAPS_T;
		}
	}
	else
	{
		this->proto_caps |= PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_C;
	}

	return &this->public;
}

