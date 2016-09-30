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
#include "tpm_tss_tss2_names.h"

#ifdef TSS_TSS2

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <bio/bio_reader.h>

#include <tpm20.h>
#include <tcti_socket.h>

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

	/**
	 * Number of supported algorithms
	 */
	size_t supported_algs_count;

	/**
	 * List of supported algorithms
	 */
	TPM_ALG_ID supported_algs[TPM_PT_ALGORITHM_SET];
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
 * Convert hash algorithm to TPM_ALG_ID
 */
static TPM_ALG_ID hash_alg_to_tpm_alg_id(hash_algorithm_t alg)
{
	switch (alg)
	{
		case HASH_SHA1:
			return TPM_ALG_SHA1;
		case HASH_SHA256:
			return TPM_ALG_SHA256;
		case HASH_SHA384:
			return TPM_ALG_SHA384;
		case HASH_SHA512:
			return TPM_ALG_SHA512;
		default:
			return TPM_ALG_ERROR;
	}
}

/**
 * Convert TPM_ALG_ID to hash algorithm
 */
static hash_algorithm_t hash_alg_from_tpm_alg_id(TPM_ALG_ID alg)
{
	switch (alg)
	{
		case TPM_ALG_SHA1:
			return HASH_SHA1;
		case TPM_ALG_SHA256:
			return HASH_SHA256;
		case TPM_ALG_SHA384:
			return HASH_SHA384;
		case TPM_ALG_SHA512:
			return HASH_SHA512;
		default:
			return HASH_UNKNOWN;
	}
}

/**
 * Check if an algorithm given by its TPM_ALG_ID is supported by the TPM
 */
static bool is_supported_alg(private_tpm_tss_tss2_t *this, TPM_ALG_ID alg_id)
{
	int i;

	if (alg_id == TPM_ALG_ERROR)
	{
		return FALSE;
	}

	for (i = 0; i < this->supported_algs_count; i++)
	{
		if (this->supported_algs[i] == alg_id)
		{
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Get a list of supported algorithms
 */
static bool get_algs_capability(private_tpm_tss_tss2_t *this)
{
	TPMS_CAPABILITY_DATA cap_data;
	TPMI_YES_NO more_data;
	TPM_ALG_ID alg;
	uint32_t rval, i;
	size_t len = BUF_LEN;
	char buf[BUF_LEN];
	char *pos = buf;
	int written;

	/* get supported algorithms */
	rval = Tss2_Sys_GetCapability(this->sys_context, 0, TPM_CAP_ALGS,
						0, TPM_PT_ALGORITHM_SET, &more_data, &cap_data, 0);
	if (rval != TPM_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s GetCapability failed for TPM_CAP_ALGS: 0x%06x",
					   LABEL, rval);
		return FALSE;
	}

	/* Number of supported algorithms */
	this->supported_algs_count = cap_data.data.algorithms.count;

	/* store and print supported algorithms */
	for (i = 0; i < this->supported_algs_count; i++)
	{
		alg = cap_data.data.algorithms.algProperties[i].alg;
		this->supported_algs[i] = alg;

		written = snprintf(pos, len, " %N", tpm_alg_id_names, alg);
		if (written < 0 || written >= len)
		{
			break;
		}
		pos += written;
		len -= written;
	}
	DBG2(DBG_PTS, "%s algorithms:%s", LABEL, buf);

	/* get supported ECC curves */
	rval = Tss2_Sys_GetCapability(this->sys_context, 0, TPM_CAP_ECC_CURVES,
						0, TPM_PT_LOADED_CURVES, &more_data, &cap_data, 0);
	if (rval != TPM_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s GetCapability failed for TPM_ECC_CURVES: 0x%06x",
					   LABEL, rval);
		return FALSE;
	}

	/* reset print buffer */
	pos = buf;
	len = BUF_LEN;

	/* print supported ECC curves */
	for (i = 0; i < cap_data.data.eccCurves.count; i++)
	{
		written = snprintf(pos, len, " %N", tpm_ecc_curve_names,
						   cap_data.data.eccCurves.eccCurves[i]);
		if (written < 0 || written >= len)
		{
			break;
		}
		pos += written;
		len -= written;
	}
	DBG2(DBG_PTS, "%s ECC curves:%s", LABEL, buf);

	return TRUE;
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

	/* get a list of supported algorithms and ECC curves */
	return get_algs_capability(this);
}

/**
 * Finalize TSS context
 */
static void finalize_context(private_tpm_tss_tss2_t *this)
{
	if (this->tcti_context)
	{
		tss2_tcti_finalize(this->tcti_context);
		free(this->tcti_context);
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

METHOD(tpm_tss_t, get_version_info, chunk_t,
	private_tpm_tss_tss2_t *this)
{
	return chunk_empty;
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
	TPM_ALG_ID sig_alg, digest_alg;
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
			TPMT_RSA_SCHEME *scheme;
			chunk_t aik_exponent, aik_modulus;

			scheme = &public.t.publicArea.parameters.rsaDetail.scheme;
			sig_alg   = scheme->scheme;
			digest_alg = scheme->details.anySig.hashAlg;

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
			TPMT_ECC_SCHEME *scheme;
			chunk_t ecc_point;
			uint8_t *pos;

			scheme = &public.t.publicArea.parameters.eccDetail.scheme;
			sig_alg   = scheme->scheme;
			digest_alg = scheme->details.anySig.hashAlg;

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
			return chunk_empty;
	}
	DBG1(DBG_PTS, "AIK signature algorithm is %N with %N hash",
		 tpm_alg_id_names, sig_alg, tpm_alg_id_names, digest_alg);
	return aik_pubkey;
}

/**
 * Configure a PCR Selection assuming a maximum of 24 registers
 */
static bool init_pcr_selection(private_tpm_tss_tss2_t *this, uint32_t pcrs,
							   hash_algorithm_t alg, TPML_PCR_SELECTION *pcr_sel)
{
	TPM_ALG_ID alg_id;
	uint32_t pcr;

	/* check if hash algorithm is supported by TPM */
	alg_id = hash_alg_to_tpm_alg_id(alg);
	if (!is_supported_alg(this, alg_id))
	{
		DBG1(DBG_PTS, "%s %N hash algorithm not supported by TPM",
			 LABEL, hash_algorithm_short_names, alg);
		return FALSE;
	}

	/* initialize the PCR Selection structure,*/
	pcr_sel->count = 1;
	pcr_sel->pcrSelections[0].hash = alg_id;
	pcr_sel->pcrSelections[0].sizeofSelect = 3;
	pcr_sel->pcrSelections[0].pcrSelect[0] = 0;
	pcr_sel->pcrSelections[0].pcrSelect[1] = 0;
	pcr_sel->pcrSelections[0].pcrSelect[2] = 0;

	/* set the selected PCRs */
	for (pcr = 0; pcr < PLATFORM_PCR; pcr++)
	{
		if (pcrs & (1 << pcr))
		{
			pcr_sel->pcrSelections[0].pcrSelect[pcr / 8] |= ( 1 << (pcr % 8) );
		}
	}
	return TRUE;
}

METHOD(tpm_tss_t, read_pcr, bool,
	private_tpm_tss_tss2_t *this, uint32_t pcr_num, chunk_t *pcr_value,
	hash_algorithm_t alg)
{
	TPML_PCR_SELECTION pcr_selection;
	TPML_DIGEST pcr_values;

	uint32_t pcr_update_counter, rval;
	uint8_t *pcr_value_ptr;
	size_t   pcr_value_len;

	if (pcr_num >= PLATFORM_PCR)
	{
		DBG1(DBG_PTS, "%s maximum number of supported PCR is %d",
					   LABEL, PLATFORM_PCR);
		return FALSE;
	}

	if (!init_pcr_selection(this, (1 << pcr_num), alg, &pcr_selection))
	{
		return FALSE;
	}

	/* initialize the PCR Digest structure */
	memset(&pcr_values, 0, sizeof(TPML_DIGEST));

	/* read the PCR value */
	rval = Tss2_Sys_PCR_Read(this->sys_context, 0, &pcr_selection,
				&pcr_update_counter, &pcr_selection, &pcr_values, 0);
	if (rval != TPM_RC_SUCCESS)
	{
		DBG1(DBG_PTS, "%s PCR bank could not be read: 0x%60x",
					   LABEL, rval);
		return FALSE;
	}
	pcr_value_ptr = (uint8_t *)pcr_values.digests[0].t.buffer;
	pcr_value_len = (size_t)   pcr_values.digests[0].t.size;

	*pcr_value = chunk_clone(chunk_create(pcr_value_ptr, pcr_value_len));

	return TRUE;
}

METHOD(tpm_tss_t, extend_pcr, bool,
	private_tpm_tss_tss2_t *this, uint32_t pcr_num, chunk_t *pcr_value,
	chunk_t data, hash_algorithm_t alg)
{
	/* TODO */
	return FALSE;
}

METHOD(tpm_tss_t, quote, bool,
	private_tpm_tss_tss2_t *this, uint32_t aik_handle, uint32_t pcr_sel,
	hash_algorithm_t alg, chunk_t data, tpm_quote_mode_t *quote_mode,
	tpm_tss_quote_info_t **quote_info, chunk_t *quote_sig)
{
	chunk_t quoted_chunk, qualified_signer, extra_data, clock_info,
			firmware_version, pcr_select, pcr_digest;
	hash_algorithm_t pcr_digest_alg;
	bio_reader_t *reader;
	uint32_t rval;

	TPM2B_DATA qualifying_data;
	TPML_PCR_SELECTION  pcr_selection;
	TPM2B_ATTEST quoted = { { sizeof(TPM2B_ATTEST)-2, } };
	TPMT_SIG_SCHEME scheme;
	TPMT_SIGNATURE sig;
	TPMI_ALG_HASH hash_alg;
	TPMS_AUTH_COMMAND  session_data_cmd;
	TPMS_AUTH_RESPONSE session_data_rsp;
	TSS2_SYS_CMD_AUTHS sessions_data_cmd;
	TSS2_SYS_RSP_AUTHS sessions_data_rsp;
	TPMS_AUTH_COMMAND  *session_data_cmd_array[1];
	TPMS_AUTH_RESPONSE *session_data_rsp_array[1];

	session_data_cmd_array[0] = &session_data_cmd;
	session_data_rsp_array[0] = &session_data_rsp;

	sessions_data_cmd.cmdAuths = &session_data_cmd_array[0];
	sessions_data_rsp.rspAuths = &session_data_rsp_array[0];

	sessions_data_cmd.cmdAuthsCount = 1;
	sessions_data_rsp.rspAuthsCount = 1;

	session_data_cmd.sessionHandle = TPM_RS_PW;
	session_data_cmd.hmac.t.size = 0;
	session_data_cmd.nonce.t.size = 0;

	*( (uint8_t *)((void *)&session_data_cmd.sessionAttributes ) ) = 0;

	qualifying_data.t.size = data.len;
	memcpy(qualifying_data.t.buffer, data.ptr, data.len);

	scheme.scheme = TPM_ALG_NULL;
	memset(&sig, 0x00, sizeof(sig));

	/* set Quote mode */
	*quote_mode = TPM_QUOTE_TPM2;

	if (!init_pcr_selection(this, pcr_sel, alg, &pcr_selection))
	{
		return FALSE;
	}

	rval = Tss2_Sys_Quote(this->sys_context, aik_handle, &sessions_data_cmd,
						  &qualifying_data, &scheme, &pcr_selection,  &quoted,
						  &sig, &sessions_data_rsp);
	if (rval != TPM_RC_SUCCESS)
	{
		DBG1(DBG_PTS,"%s Tss2_Sys_Quote failed: 0x%06x", LABEL, rval);
		return FALSE;
	}
	quoted_chunk = chunk_create(quoted.t.attestationData, quoted.t.size);

	reader = bio_reader_create(chunk_skip(quoted_chunk, 6));
	if (!reader->read_data16(reader, &qualified_signer) ||
		!reader->read_data16(reader, &extra_data) ||
		!reader->read_data  (reader, 17, &clock_info) ||
		!reader->read_data  (reader,  8, &firmware_version) ||
		!reader->read_data  (reader, 10, &pcr_select) ||
		!reader->read_data16(reader, &pcr_digest))
	{
		DBG1(DBG_PTS, "%s parsing of quoted struct failed", LABEL);
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);

	DBG2(DBG_PTS, "PCR Composite digest: %B", &pcr_digest);
	DBG2(DBG_PTS, "TPM Quote Info: %B", &quoted_chunk);
	DBG2(DBG_PTS, "qualifiedSigner: %B", &qualified_signer);
	DBG2(DBG_PTS, "extraData: %B", &extra_data);
	DBG2(DBG_PTS, "clockInfo: %B", &clock_info);
	DBG2(DBG_PTS, "firmwareVersion: %B", &firmware_version);
	DBG2(DBG_PTS, "pcrSelect: %B", &pcr_select);

	/* extract signature */
	switch (sig.sigAlg)
	{
		case TPM_ALG_RSASSA:
		case TPM_ALG_RSAPSS:
			*quote_sig = chunk_clone(
							chunk_create(
								sig.signature.rsassa.sig.t.buffer,
								sig.signature.rsassa.sig.t.size));
			hash_alg = sig.signature.rsassa.hash;
			break;
		case TPM_ALG_ECDSA:
		case TPM_ALG_ECDAA:
		case TPM_ALG_SM2:
		case TPM_ALG_ECSCHNORR:
			*quote_sig = chunk_cat("cc",
							chunk_create(
								sig.signature.ecdsa.signatureR.t.buffer,
								sig.signature.ecdsa.signatureR.t.size),
							chunk_create(
								sig.signature.ecdsa.signatureS.t.buffer,
								sig.signature.ecdsa.signatureS.t.size));
			hash_alg = sig.signature.ecdsa.hash;
			break;
		default:
			DBG1(DBG_PTS, "%s unsupported %N signature algorithm",
						   LABEL, tpm_alg_id_names, sig.sigAlg);
			return FALSE;
	};

	DBG2(DBG_PTS, "PCR digest algorithm is %N", tpm_alg_id_names, hash_alg);
	pcr_digest_alg = hash_alg_from_tpm_alg_id(hash_alg);

	DBG2(DBG_PTS, "TPM Quote Signature: %B", quote_sig);

	/* Create and initialize Quote Info object */
	*quote_info = tpm_tss_quote_info_create(*quote_mode, pcr_digest_alg,
														 pcr_digest);
	(*quote_info)->set_tpm2_info(*quote_info, qualified_signer, clock_info,
														 pcr_select);
	(*quote_info)->set_version_info(*quote_info, firmware_version);

	return TRUE;
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
			.get_version_info = _get_version_info,
			.generate_aik = _generate_aik,
			.get_public = _get_public,
			.read_pcr = _read_pcr,
			.extend_pcr = _extend_pcr,
			.quote = _quote,
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


