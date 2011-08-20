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
	 * Contains a TPM_CAP_VERSION_INFO struct
	 */
	chunk_t tpm_version_info;
};

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
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;

	if (!this->tpm_version_info.ptr)
	{
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
	}
	*info = this->tpm_version_info;
	print_tpm_version_info(this);
	return TRUE;

err:
	DBG1(DBG_TNC, "could not get tpm version info: tss error 0x%x", result);
	return FALSE;	
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
 * See header
 */
pts_t *pts_create(void)
{
	private_pts_t *this;

	INIT(this,
		.public = {
			.get_tpm_version_info = _get_tpm_version_info,
			.set_tpm_version_info = _set_tpm_version_info,
			.destroy = _destroy,
		},
	);

	return &this->public;
}

