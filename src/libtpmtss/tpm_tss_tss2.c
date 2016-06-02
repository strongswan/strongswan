/*
 * Copyright (C) 2016 Andreas Steffen
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

#include "tpm_tss_tss2.h"

#ifdef TSS_TSS2

#include <asn1/asn1.h>
#include <asn1/oid.h>

#include <tss2/tpm20.h>
#include <tcti/tcti_socket.h>

#define LABEL	"TPM 2.0 -"

typedef struct private_tpm_tss_tss2_t private_tpm_tss_tss2_t;

/**
 * Private data of an tpm_tss_tss2_t object.
 */
struct private_tpm_tss_tss2_t {

	/**
	 * Public tpm_tss_tss2_t interface.
	 */
	tpm_tss_t public;

	/**
	 * TCTI context
	 */
	TSS2_TCTI_CONTEXT *tcti_context;

	/**
	 * SYS context
	 */
	TSS2_SYS_CONTEXT  *sys_context;

};

/**
 * Some symbols required by libtctisocket
 */
FILE *outFp;
uint8_t simulator = 1;

int TpmClientPrintf (uint8_t type, const char *format, ...)
{
    return 0;
}

/**
 * Initialize TSS context
 */
static bool initialize_context(private_tpm_tss_tss2_t *this)
{
	size_t   tcti_context_size;
	uint32_t sys_context_size;
	uint32_t rval;

	TCTI_SOCKET_CONF rm_if_config = { DEFAULT_HOSTNAME,
									  DEFAULT_RESMGR_TPM_PORT
									};

	TSS2_ABI_VERSION abi_version = { TSSWG_INTEROP,
									 TSS_SAPI_FIRST_FAMILY,
									 TSS_SAPI_FIRST_LEVEL,
									 TSS_SAPI_FIRST_VERSION
								   };

	/* determine size of tcti context */
	rval = InitSocketTcti(NULL, &tcti_context_size, &rm_if_config, 0);
	if (rval != TSS2_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s could not get tcti_context size: 0x%06x",
					   LABEL, rval);
		return FALSE;
	}

	/* allocate memory for tcti context */
	this->tcti_context = (TSS2_TCTI_CONTEXT*)malloc(tcti_context_size);

	/* initialize tcti context */
	rval = InitSocketTcti(this->tcti_context, &tcti_context_size,
						  &rm_if_config, 0);
	if (rval != TSS2_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s could not get tcti_context: 0x%06x",
					   LABEL, rval);
		return FALSE;
	}

	/* determine size of sys context */
	sys_context_size = Tss2_Sys_GetContextSize(0);

	/* allocate memory for sys context */
	this->sys_context = malloc(sys_context_size);

	/* initialize sys context */
	rval = Tss2_Sys_Initialize(this->sys_context, sys_context_size,
							   this->tcti_context, &abi_version);
	if (rval != TSS2_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s could not get sys_context: 0x%06x",
					   LABEL, rval);
		return FALSE;
	}
	return TRUE;
}

/**
 * Finalize TSS context
 */
static void finalize_context(private_tpm_tss_tss2_t *this)
{
	if (this->tcti_context)
	{
		TeardownSocketTcti(this->tcti_context);
	}
	if (this->sys_context)
	{
		Tss2_Sys_Finalize(this->sys_context);
		free(this->sys_context);
	}
}

METHOD(tpm_tss_t, get_version, tpm_version_t,
	private_tpm_tss_tss2_t *this)
{
	return TPM_VERSION_2_0;
}

/**
 * read the public key portion of a TSS 2.0 AIK key from NVRAM
 */
bool read_public(private_tpm_tss_tss2_t *this, TPMI_DH_OBJECT handle,
	TPM2B_PUBLIC *public)
{
	uint32_t rval;

	TPM2B_NAME name = { { sizeof(TPM2B_NAME)-2, } };
	TPM2B_NAME qualified_name = { { sizeof(TPM2B_NAME)-2, } };

	TPMS_AUTH_RESPONSE session_data;
	TSS2_SYS_RSP_AUTHS sessions_data;
	TPMS_AUTH_RESPONSE *session_data_array[1];

	session_data_array[0]  = &session_data;
	sessions_data.rspAuths = &session_data_array[0];
	sessions_data.rspAuthsCount = 1;

	/* always send simulator platform command, ignored by true RM */
	PlatformCommand(this->tcti_context ,MS_SIM_POWER_ON );
	PlatformCommand(this->tcti_context, MS_SIM_NV_ON );

	/* read public key for a given object handle from TPM 2.0 NVRAM */
	rval = Tss2_Sys_ReadPublic(this->sys_context, handle, 0, public, &name,
							   &qualified_name, &sessions_data);

	PlatformCommand(this->tcti_context, MS_SIM_POWER_OFF);

	if (rval != TPM_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s could not read public key from handle 0x%08x: 0x%06x",
					   LABEL, handle, rval);
		return FALSE;
	}
	return TRUE;
}

METHOD(tpm_tss_t, generate_aik, bool,
	private_tpm_tss_tss2_t *this, chunk_t ca_modulus, chunk_t *aik_blob,
	chunk_t *aik_pubkey, chunk_t *identity_req)
{
	return FALSE;
}

METHOD(tpm_tss_t, get_public, chunk_t,
	private_tpm_tss_tss2_t *this, uint32_t handle)
{
	TPM2B_PUBLIC public = { { 0, } };
	chunk_t aik_blob, aik_pubkey = chunk_empty;

	if (!read_public(this, handle, &public))
	{
		return chunk_empty;
	}

	aik_blob = chunk_create((u_char*)&public, sizeof(public));
	DBG3(DBG_LIB, "%s AIK public key blob: %B", LABEL, &aik_blob);

	/* convert TSS 2.0 AIK public key blot into PKCS#1 format */
	switch (public.t.publicArea.type)
	{
		case TPM_ALG_RSA:
		{
			TPM2B_PUBLIC_KEY_RSA *rsa;
			chunk_t aik_exponent, aik_modulus;

			rsa = &public.t.publicArea.unique.rsa;
			aik_modulus = chunk_create(rsa->t.buffer, rsa->t.size);
			aik_exponent = chunk_from_chars(0x01, 0x00, 0x01);

			/* subjectPublicKeyInfo encoding of AIK RSA key */
			if (!lib->encoding->encode(lib->encoding, PUBKEY_SPKI_ASN1_DER,
					NULL, &aik_pubkey, CRED_PART_RSA_MODULUS, aik_modulus,
					CRED_PART_RSA_PUB_EXP, aik_exponent, CRED_PART_END))
			{
				DBG1(DBG_PTS, "%s subjectPublicKeyInfo encoding of AIK key "
							  "failed", LABEL);
			}
			break;
		}
		case TPM_ALG_ECC:
		{
			TPMS_ECC_POINT *ecc;
			chunk_t ecc_point;
			uint8_t *pos;

			ecc = &public.t.publicArea.unique.ecc;

			/* allocate space for bit string */
			pos = asn1_build_object(&ecc_point, ASN1_BIT_STRING,
									2 + ecc->x.t.size + ecc->y.t.size);
			/* bit string length is a multiple of octets */
			*pos++ = 0x00;
			/* uncompressed ECC point format */
			*pos++ = 0x04;
			/* copy x coordinate of ECC point */
			memcpy(pos, ecc->x.t.buffer, ecc->x.t.size);
			pos += ecc->x.t.size;
			/* copy y coordinate of ECC point */
			memcpy(pos, ecc->y.t.buffer, ecc->y.t.size);
			/* subjectPublicKeyInfo encoding of AIK ECC key */
			aik_pubkey = asn1_wrap(ASN1_SEQUENCE, "mm",
							asn1_wrap(ASN1_SEQUENCE, "mm",
								asn1_build_known_oid(OID_EC_PUBLICKEY),
								asn1_build_known_oid(ecc->x.t.size == 32 ?
										OID_PRIME256V1 : OID_SECT384R1)),
							ecc_point);
			break;
		}
		default:
			DBG1(DBG_PTS, "%s unsupported AIK key type", LABEL);
	}

	return aik_pubkey;
}

METHOD(tpm_tss_t, destroy, void,
	private_tpm_tss_tss2_t *this)
{
	finalize_context(this);
	free(this);
}

/**
 * See header
 */
tpm_tss_t *tpm_tss_tss2_create()
{
	private_tpm_tss_tss2_t *this;
	bool available;

	INIT(this,
		.public = {
			.get_version = _get_version,
			.generate_aik = _generate_aik,
			.get_public = _get_public,
			.destroy = _destroy,
		},
	);

	available = initialize_context(this);
	DBG1(DBG_PTS, "TPM 2.0 via TSS2 %savailable", available ? "" : "not ");

	if (!available)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#else /* TSS_TSS2 */

tpm_tss_t *tpm_tss_tss2_create()
{
	return NULL;
}

#endif /* TSS_TSS2 */


