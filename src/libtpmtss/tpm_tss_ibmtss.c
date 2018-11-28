/*
 *
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2018 Semihalf
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

#include "tpm_tss_ibmtss.h"

#ifdef TSS_IBMTSS

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <bio/bio_reader.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>

#define LABEL	"TPM 2.0 -"

#define PLATFORM_PCR	24

typedef struct tpm_tss_ibmtss_sc tpm_tss_ibmtss_sc;

/**
 * Private data of an tpm_tss_ibmtss object.
 */
struct tpm_tss_ibmtss_sc {
	tpm_tss_t public;

	TSS_CONTEXT *context;

	size_t supported_algs_count;

	TPM_ALG_ID supported_algs[TPM_PT_ALGORITHM_SET];

	bool fips_186_4;

	 /**
	  * TPM_PT_INPUT_BUFFER - the maximum size of data
	  * send as argument to TPM. Read in get_algs_capability.
	  */
	size_t max_input_size;
};


/**
 * Pointers for error messages
 */
static const char *rc_msg, *rc_submsg, *rc_num;

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
 * Get a list of supported algorithms
 */
static bool get_algs_capability(tpm_tss_ibmtss_sc *this)
{
	TPMS_TAGGED_PROPERTY tp;
	TPM_ALG_ID alg;
	GetCapability_In in;
	GetCapability_Out out;
	TPM_RC rc;

	bool fips_140_2;

	uint32_t i, offset, revision = 0, year = 0;
	char manufacturer[5], vendor_string[17];

	in.capability = TPM_CAP_TPM_PROPERTIES;
	in.property = PT_FIXED;
	in.propertyCount = MAX_TPM_PROPERTIES;

	/* get fixed properties */
	rc = TSS_Execute(this->context,
				(RESPONSE_PARAMETERS*) &out,
				(COMMAND_PARAMETERS*) &in,
				NULL,
				TPM_CC_GetCapability,
				TPM_RH_NULL, NULL, 0);
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS, "%s GetCapability failed for TPM2_CAP_TPM_PROPERTIES: %s%s%s",
		  LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}
	memset(manufacturer,  '\0', sizeof(manufacturer));
	memset(vendor_string, '\0', sizeof(vendor_string));

	/* print fixed properties */
	for (i = 0; i < out.capabilityData.data.tpmProperties.count; i++)
	{
		tp = out.capabilityData.data.tpmProperties.tpmProperty[i];
		switch (tp.property)
		{
			case TPM_PT_REVISION:
				revision = tp.value;
				break;
			case TPM_PT_YEAR:
				year = tp.value;
				break;
			case TPM_PT_MANUFACTURER:
				htoun32(manufacturer, tp.value);
				break;
			case TPM_PT_VENDOR_STRING_1:
			case TPM_PT_VENDOR_STRING_2:
			case TPM_PT_VENDOR_STRING_3:
			case TPM_PT_VENDOR_STRING_4:
				offset = 4 * (tp.property - TPM_PT_VENDOR_STRING_1);
				htoun32(vendor_string + offset, tp.value);
				break;
			case TPM_PT_MODES:
				if (tp.value & TPMA_MODES_FIPS_140_2)
				{
					this->fips_186_4 = fips_140_2 = TRUE;
				}
				break;
			case TPM_PT_INPUT_BUFFER:
				this->max_input_size = tp.value;
				break;
			default:
				break;
		}
	}

	/* The minimal value of TPM_PT_INPUT_BUFFER is 1024 */
	if (this->max_input_size == 0)
		this->max_input_size = 1024;

	if (!fips_140_2)
	{
		this->fips_186_4 = lib->settings->get_bool(lib->settings,
					"%s.plugins.tpm.fips_186_4", FALSE, lib->ns);
	}
	DBG2(DBG_PTS, "%s manufacturer: %s (%s) rev: %05.2f %u %s", LABEL,
		 manufacturer, vendor_string, (float)revision/100, year,
		 fips_140_2 ? "FIPS 140-2" : (this->fips_186_4 ? "FIPS 186-4" : ""));

	in.capability = TPM_CAP_ALGS;
	in.property = 0;
	in.propertyCount = TPM_PT_ALGORITHM_SET;

	/* get supported algorithms */
	rc = TSS_Execute(this->context,
				(RESPONSE_PARAMETERS*) &out,
				(COMMAND_PARAMETERS*) &in,
				NULL,
				TPM_CC_GetCapability,
				TPM_RH_NULL, NULL, 0);
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS, "%s GetCapability failed for TPM2_CAP_ALGS: %s%s%s",
		  LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}

	/* Number of supported algorithms */
	this->supported_algs_count = out.capabilityData.data.algorithms.count;

	/* store supported algorithms */
	for (i = 0; i < this->supported_algs_count; i++)
	{
		alg = out.capabilityData.data.algorithms.algProperties[i].alg;
		this->supported_algs[i] = alg;
	}

	return TRUE;
}


/**
 * Check if an algorithm given by its TPM_ALG_ID is supported by the TPM
 */
static bool is_supported_alg(tpm_tss_ibmtss_sc *this, TPM_ALG_ID alg_id)
{
  int i;

	return TRUE;

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


METHOD(tpm_tss_t, get_version, tpm_version_t,
    tpm_tss_ibmtss_sc *this)
{
  return TPM_VERSION_2_0;
}

METHOD(tpm_tss_t, get_version_info, chunk_t,
    tpm_tss_ibmtss_sc *this)
{
  return chunk_empty;
}

/**
 * read the public key portion of a TSS 2.0 key
 */
bool read_public(tpm_tss_ibmtss_sc *this, TPMI_DH_OBJECT handle,
	TPM2B_PUBLIC *key)
{
	TPM_RC rc;
	ReadPublic_In in;
	ReadPublic_Out out;

	in.objectHandle = handle;

	rc = TSS_Execute(this->context,
		(RESPONSE_PARAMETERS*) &out,
		(COMMAND_PARAMETERS*) &in,
		NULL,
		TPM_CC_ReadPublic,
		TPM_RH_NULL, NULL, 0);
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS, "%s could not read public key: %s%s%s",
		  LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}

	memcpy(key, &out.outPublic, sizeof(TPM2B_PUBLIC));
	return TRUE;
}


METHOD(tpm_tss_t, generate_aik, bool,
	tpm_tss_ibmtss_sc *this, chunk_t ca_modulus, chunk_t *aik_blob,
	chunk_t *aik_pubkey, chunk_t *identity_req)
{
	return FALSE;
}

METHOD(tpm_tss_t, get_public, chunk_t,
	tpm_tss_ibmtss_sc *this, uint32_t handle)
{
	TPM2B_PUBLIC public = { 0, };
	chunk_t aik_blob, aik_pubkey = chunk_empty;

	if (!read_public(this, handle, &public))
	{
		return chunk_empty;
	}

	aik_blob = chunk_create((u_char*)&public, sizeof(public));
	DBG3(DBG_LIB, "%s AIK public key blob: %B", LABEL, &aik_blob);

	/* convert TSS 2.0 AIK public key blob into PKCS#1 format */
	switch (public.publicArea.type)
	{
		case TPM_ALG_RSA:
		{
			TPM2B_PUBLIC_KEY_RSA *rsa;
			TPMS_RSA_PARMS *rsa_parms;
			chunk_t aik_exponent, aik_modulus;

			rsa = &public.publicArea.unique.rsa;
			rsa_parms = &public.publicArea.parameters.rsaDetail;
			aik_modulus = chunk_create(rsa->t.buffer, rsa->t.size);
			if (rsa_parms->exponent == 0) {
				aik_exponent = chunk_from_chars(0x01, 0x00, 0x01);
			}
			else
				aik_exponent = chunk_from_thing(rsa_parms->exponent);

			/* subjectPublicKeyInfo encoding of AIK RSA key */
			if (!lib->encoding->encode(lib->encoding, PUBKEY_SPKI_ASN1_DER,
					NULL, &aik_pubkey, CRED_PART_RSA_MODULUS, aik_modulus,
					CRED_PART_RSA_PUB_EXP, aik_exponent, CRED_PART_END))
			{
				DBG1(DBG_PTS, "%s subjectPublicKeyInfo encoding of AIK key "
							  "failed", LABEL);
				return chunk_empty;
			}
			break;
		}
		case TPM_ALG_ECC:
		{
			TPMS_ECC_POINT *ecc;
			chunk_t ecc_point;
			uint8_t *pos;

			ecc = &public.publicArea.unique.ecc;

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
	return aik_pubkey;
}

METHOD(tpm_tss_t, supported_signature_schemes, enumerator_t*,
	tpm_tss_ibmtss_sc *this, uint32_t handle)
{
	TPM2B_PUBLIC public = { 0, };
	hash_algorithm_t digest;
	signature_params_t supported_scheme;

	if (!read_public(this, handle, &public))
	{
		return enumerator_create_empty();
	}

	switch (public.publicArea.type)
	{
		case TPM_ALG_RSA:
		{
			TPMS_RSA_PARMS *rsa;
			TPMT_RSA_SCHEME *scheme;
			ssize_t salt_len;

			salt_len = this->fips_186_4 ? RSA_PSS_SALT_LEN_DEFAULT :
						RSA_PSS_SALT_LEN_MAX;

			rsa = &public.publicArea.parameters.rsaDetail;
			scheme = &rsa->scheme;
			digest = hash_alg_from_tpm_alg_id(scheme->details.anySig.hashAlg);

			switch (scheme->scheme)
			{
				case TPM_ALG_RSAPSS:
				{
					rsa_pss_params_t pss_params = {
						.hash = digest,
						.mgf1_hash = digest,
						.salt_len = salt_len,
					};
					supported_scheme = (signature_params_t){
						.scheme = SIGN_RSA_EMSA_PSS,
						.params = &pss_params,
					};
					if (!rsa_pss_params_set_salt_len(&pss_params, rsa->keyBits))
					{
						return enumerator_create_empty();
					}
					break;
				}
				case TPM_ALG_RSASSA:
					supported_scheme = (signature_params_t){
						.scheme = signature_scheme_from_oid(
									hasher_signature_algorithm_to_oid(digest,
																	  KEY_RSA)),
					};
					break;
				/* TPM_ALG_NULL indicates that the key
				 * supports any hashing algorithm supported by the chip.
				 */
				case TPM_ALG_NULL:
				{
					rsa_pss_params_t pss_params = {
						.hash = HASH_SHA256,
						.mgf1_hash = HASH_SHA256,
						.salt_len = salt_len,
					};
					supported_scheme = (signature_params_t){
						.scheme = SIGN_RSA_EMSA_PSS,
						.params = &pss_params,
					};
				}
				default:
					return enumerator_create_empty();
			}
			break;
		}
		case TPM_ALG_ECC:
		{
			TPMT_ECC_SCHEME *scheme;

			scheme = &public.publicArea.parameters.eccDetail.scheme;
			digest = hash_alg_from_tpm_alg_id(scheme->details.anySig.hashAlg);

			switch (scheme->scheme)
			{
				case TPM_ALG_ECDSA:
					supported_scheme = (signature_params_t){
						.scheme = signature_scheme_from_oid(
									hasher_signature_algorithm_to_oid(digest,
																	KEY_ECDSA)),
					};
					break;
				/* TPM_ALG_NULL indicates that the key
				 * supports any hashing algorithm supported by the chip.
				 */
				case TPM_ALG_NULL:
					supported_scheme = (signature_params_t){
						.scheme = signature_scheme_from_oid(
									hasher_signature_algorithm_to_oid(HASH_SHA256,
																	KEY_ECDSA)),
					};

					break;
				default:
					return enumerator_create_empty();
			}
			break;
		}
		default:
			DBG1(DBG_PTS, "%s unsupported key type", LABEL);
			return enumerator_create_empty();
	}
	return enumerator_create_single(signature_params_clone(&supported_scheme),
									(void*)signature_params_destroy);
}


METHOD(tpm_tss_t, read_pcr, bool,
	tpm_tss_ibmtss_sc *this, uint32_t pcr_num, chunk_t *pcr_value,
	hash_algorithm_t alg)
{
	return FALSE;
}

METHOD(tpm_tss_t, extend_pcr, bool,
	tpm_tss_ibmtss_sc *this, uint32_t pcr_num, chunk_t *pcr_value,
	chunk_t data, hash_algorithm_t alg)
{
	return FALSE;
}

METHOD(tpm_tss_t, quote, bool,
    tpm_tss_ibmtss_sc *this, uint32_t aik_handle, uint32_t pcr_sel,
    hash_algorithm_t alg, chunk_t data, tpm_quote_mode_t *quote_mode,
    tpm_tss_quote_info_t **quote_info, chunk_t *quote_sig)
{
	return FALSE;
}

static bool gen_hash(tpm_tss_ibmtss_sc *this, TPMI_ALG_HASH halg,
    uint32_t hierarchy, chunk_t data, TPM2B_DIGEST *digest, TPMT_TK_HASHCHECK *ticket)
{
	size_t length = data.len;

	TPM_RC rc;

	Hash_In hash_in;
	Hash_Out hash_out;

	if (length <= this->max_input_size)
	{
		memcpy(hash_in.data.t.buffer, data.ptr, length);
		hash_in.data.t.size = length;
		hash_in.hierarchy = hierarchy;
		hash_in.hashAlg = halg;

		rc = TSS_Execute(this->context,
			(RESPONSE_PARAMETERS*) &hash_out,
			(COMMAND_PARAMETERS*) &hash_in,
			NULL,
			TPM_CC_Hash,
			TPM_RH_NULL, NULL, 0);
		if (rc != TPM_RC_SUCCESS)
		{
			TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
			DBG1(DBG_PTS,"%s Hash command failed: %s%s%s",
			  LABEL, rc_msg, rc_submsg, rc_num);
			return FALSE;
		}

		memcpy(ticket, &hash_out.validation, sizeof(TPMT_TK_HASHCHECK));
		memcpy(digest, &hash_out.outHash, sizeof(TPM2B_DIGEST));
		return TRUE;
	}
	DBG1(DBG_PTS, "%s Provided input is too long to hash\n", LABEL);
	return FALSE;
}

METHOD(tpm_tss_t, sign, bool,
	tpm_tss_ibmtss_sc *this, uint32_t hierarchy, uint32_t handle,
	signature_scheme_t scheme, void *params, chunk_t data, chunk_t pin,
	chunk_t *signature)
{
	key_type_t key_type;
	hash_algorithm_t hash_alg;
	rsa_pss_params_t *rsa_pss_params;
	hasher_t *hasher;
	char *password = NULL;
	TPM_RC rc;

	bool unrestricted = FALSE;

	Sign_In in;
	Sign_Out out;

	TPM_ALG_ID alg_id;
	TPM2B_PUBLIC public = { 0, };

	if (scheme == SIGN_RSA_EMSA_PSS)
	{
		key_type = KEY_RSA;
		rsa_pss_params = (rsa_pss_params_t *)params;
		hash_alg = rsa_pss_params->hash;
	}
	else
	{
		key_type = key_type_from_signature_scheme(scheme);
		hash_alg = hasher_from_signature_scheme(scheme, NULL);
	}

	/* Check if hash algorithm is supported by TPM */
	alg_id = hash_alg_to_tpm_alg_id(hash_alg);
	if (!is_supported_alg(this, alg_id))
	{
		return FALSE;
	}

	/* Get public key */
	if (!read_public(this, handle, &public))
	{
		return FALSE;
	}

	unrestricted =
		!(public.publicArea.objectAttributes.val & TPMA_OBJECT_RESTRICTED);

	if (key_type == KEY_RSA && public.publicArea.type == TPM_ALG_RSA)
	{
		if (scheme == SIGN_RSA_EMSA_PSS)
		{
			in.inScheme.scheme = TPM_ALG_RSAPSS;
			in.inScheme.details.rsapss.hashAlg = alg_id;
		}
		else
		{
			in.inScheme.scheme = TPM_ALG_RSASSA;
			in.inScheme.details.rsassa.hashAlg = alg_id;
		}
	}
	else if (key_type == KEY_ECDSA && public.publicArea.type == TPM_ALG_ECC)
	{
		in.inScheme.scheme = TPM_ALG_ECDSA;
		in.inScheme.details.ecdsa.hashAlg = alg_id;

	}
	else
	{
		return FALSE;
	}

	in.keyHandle = handle;

	if (unrestricted)
	{
		hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
		if (!hasher->get_hash(hasher, data, in.digest.t.buffer)) {
			DBG1(DBG_PTS, "%s Failed to generate hash\n", LABEL);
			return FALSE;
		}

		in.digest.t.size = hasher->get_hash_size(hasher);

		in.validation.tag = TPM_ST_HASHCHECK;
		in.validation.hierarchy = TPM_RH_NULL;
		in.validation.digest.t.size = 0;
		hasher->destroy(hasher);
	}
	else
	{
		if(!gen_hash(this, alg_id, hierarchy, data, &in.digest, &in.validation))
		{
			DBG1(DBG_PTS, "%s Failed to generate hash\n", LABEL);
			return FALSE;
		}
	}

	/* Password passed in chunk_t is not 0 terminated...
	 * Work around it by passing it through a buffer.
	 */
	if (pin.len > 0)
	{
		password = malloc(pin.len+1);
		memcpy(password, pin.ptr, pin.len);
		password[pin.len] = 0;
	}

	rc = TSS_Execute(this->context,
				(RESPONSE_PARAMETERS*) &out,
				(COMMAND_PARAMETERS*) &in,
				NULL,
				TPM_CC_Sign,
				TPM_RS_PW, password, 0,
				TPM_RH_NULL, NULL, 0);
	if (password != NULL)
	{
		free(password);
	}
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS,"%s Sign command failed: %s%s%s",
		  LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}

	/* extract signature */
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_SHA1:
		case SIGN_RSA_EMSA_PKCS1_SHA2_256:
		case SIGN_RSA_EMSA_PKCS1_SHA2_384:
		case SIGN_RSA_EMSA_PKCS1_SHA2_512:
			*signature = chunk_clone(
							chunk_create(
								out.signature.signature.rsassa.sig.t.buffer,
								out.signature.signature.rsassa.sig.t.size));
			break;
		case SIGN_RSA_EMSA_PSS:
			*signature = chunk_clone(
							chunk_create(
								out.signature.signature.rsapss.sig.t.buffer,
								out.signature.signature.rsapss.sig.t.size));
			break;
		case SIGN_ECDSA_256:
		case SIGN_ECDSA_384:
		case SIGN_ECDSA_521:
			*signature = chunk_cat("cc",
							chunk_create(
								out.signature.signature.ecdsa.signatureR.t.buffer,
								out.signature.signature.ecdsa.signatureR.t.size),
							chunk_create(
								out.signature.signature.ecdsa.signatureS.t.buffer,
								out.signature.signature.ecdsa.signatureS.t.size));
			break;
		case SIGN_ECDSA_WITH_SHA256_DER:
		case SIGN_ECDSA_WITH_SHA384_DER:
		case SIGN_ECDSA_WITH_SHA512_DER:
			*signature = asn1_wrap(ASN1_SEQUENCE, "mm",
							asn1_integer("c",
								chunk_skip_zero(chunk_create(
									out.signature.signature.ecdsa.signatureR.t.buffer,
									out.signature.signature.ecdsa.signatureR.t.size))),
							asn1_integer("c",
								chunk_skip_zero(chunk_create(
									out.signature.signature.ecdsa.signatureS.t.buffer,
									out.signature.signature.ecdsa.signatureS.t.size))));
			break;
		default:
			return FALSE;
	};

	return TRUE;
}

METHOD(tpm_tss_t, get_random, bool,
	tpm_tss_ibmtss_sc *this, size_t bytes, uint8_t *buffer)
{
	GetRandom_In in;
	GetRandom_Out out;
	TPM_RC rc;
	size_t bytes_to_copy;

	while (bytes > 0)
	{
		in.bytesRequested = MIN(bytes, MAX_DIGEST_SIZE);

		rc = TSS_Execute(this->context,
			(RESPONSE_PARAMETERS*) &out,
			(COMMAND_PARAMETERS*) &in,
			NULL,
			TPM_CC_GetRandom,
			TPM_RH_NULL, NULL, 0);
		if (rc != TPM_RC_SUCCESS)
		{
			TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
			DBG1(DBG_PTS,"%s GetRandom command failed: %s%s%s",
			  LABEL, rc_msg, rc_submsg, rc_num);
			return FALSE;
		}

		bytes_to_copy = MIN(bytes, out.randomBytes.t.size);

		memcpy(buffer, out.randomBytes.t.buffer, bytes_to_copy);
		buffer += bytes_to_copy;
		bytes  -= bytes_to_copy;
  }

  return TRUE;
}

METHOD(tpm_tss_t, get_data, bool,
	tpm_tss_ibmtss_sc *this, uint32_t hierarchy, uint32_t handle,
	chunk_t pin, chunk_t *data)
{
	uint16_t max_data_size, nv_size, nv_offset = 0;
	char *password = NULL;
	TPM_RC rc;

	GetCapability_In caps_in;
	GetCapability_Out caps_out;
	NV_ReadPublic_In nv_size_in;
	NV_ReadPublic_Out nv_size_out;
	NV_Read_In nv_in;
	NV_Read_Out nv_out;

	caps_in.capability = TPM_CAP_TPM_PROPERTIES;
	caps_in.property = TPM_PT_NV_BUFFER_MAX;
	caps_in.propertyCount = 1;

	nv_size_in.nvIndex = handle;

	/* query maximum TPM data transmission size */
	rc = TSS_Execute(this->context,
				(RESPONSE_PARAMETERS*) &caps_out,
				(COMMAND_PARAMETERS*) &caps_in,
				NULL,
				TPM_CC_GetCapability,
				TPM_RH_NULL, NULL, 0);
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS,"%s GetCapability failed for "
		  "TPM2_CAP_TPM_PROPERTIES: %s%s%s", LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}
	max_data_size = min(caps_out.capabilityData.data.tpmProperties.tpmProperty[0].value,
						MAX_NV_BUFFER_SIZE);

	/* get size of NV object */
	rc = TSS_Execute(this->context,
				(RESPONSE_PARAMETERS*) &nv_size_out,
				(COMMAND_PARAMETERS*) &nv_size_in,
				NULL,
				TPM_CC_NV_ReadPublic,
				TPM_RH_NULL, NULL, 0);
	if (rc != TPM_RC_SUCCESS)
	{
		TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
		DBG1(DBG_PTS,"%s NV_ReadPublic command failed: %s%s%s",
		  LABEL, rc_msg, rc_submsg, rc_num);
		return FALSE;
	}

	nv_size = nv_size_out.nvPublic.nvPublic.dataSize;
	*data = chunk_alloc(nv_size);

	nv_in.authHandle = handle;
	nv_in.nvIndex = handle;

	/**
	 * Password passed in chunk_t is not 0 terminated...
	 * Work around it by passing it through a buffer.
	 */
	if (pin.len > 0) {
		password = malloc(pin.len+1);
		memcpy(password, pin.ptr, pin.len);
		password[pin.len] = 0;
	}

	/**
	 * Read NV data a maximum data size block at a time.
	 */
	while (nv_size > 0)
	{
		nv_in.size = MIN(max_data_size, nv_size);
		nv_in.offset = nv_offset;
		rc = TSS_Execute(this->context,
					(RESPONSE_PARAMETERS*) &nv_out,
					(COMMAND_PARAMETERS*) &nv_in,
					NULL,
					TPM_CC_NV_Read,
					TPM_RS_PW, password, 0,
					TPM_RH_NULL, NULL, 0);
		if (rc != TPM_RC_SUCCESS)
		{
			if (password != NULL)
			{
				free(password);
			}
			TSS_ResponseCode_toString(&rc_msg, &rc_submsg, &rc_num, rc);
			DBG1(DBG_PTS,"%s NV_Read command failed: %s%s%s",
			  LABEL, rc_msg, rc_submsg, rc_num);
			chunk_free(data);
			return FALSE;
		}

		memcpy(data->ptr + nv_offset, nv_out.data.t.buffer, nv_out.data.t.size);
		nv_offset += nv_out.data.t.size;
		nv_size   -= nv_out.data.t.size;
	}

	if (password != NULL)
	{
		free(password);
	}

	return TRUE;
}

METHOD(tpm_tss_t, destroy, void,
	tpm_tss_ibmtss_sc *this)
{
	if (this->context != NULL)
		TSS_Delete(this->context);

	free(this);
}

tpm_tss_t *tpm_tss_ibmtss_create()
{
	tpm_tss_ibmtss_sc *this;
	TPM_RC rc;

	INIT(this,
		.public = {
			.get_version = _get_version,
			.get_version_info = _get_version_info,
			.generate_aik = _generate_aik,
			.get_public = _get_public,
			.supported_signature_schemes = _supported_signature_schemes,
			.read_pcr = _read_pcr,
			.extend_pcr = _extend_pcr,
			.quote = _quote,
			.sign = _sign,
			.get_random = _get_random,
			.get_data = _get_data,
			.destroy = _destroy,
		}
	);

	rc = TSS_Create(&this->context);
	if (rc != TPM_RC_SUCCESS) {
		_destroy(this);
		return NULL;
	}

	/**
	 * Store all state bin files in tmp directory
	 */
	rc = TSS_SetProperty(this->context, TPM_DATA_DIR, "/tmp");
	if (rc != TPM_RC_SUCCESS) {
		_destroy(this);
		return NULL;
	}

	if (!get_algs_capability(this)) {
		_destroy(this);
		return NULL;
	}

	return &this->public;
}

bool tpm_tss_ibmtss_init(void)
{
	return TRUE;
}

void tpm_tss_ibmtss_deinit(void)
{
}
#else /* TSS_IBMTSS */

tpm_tss_t *tpm_tss_ibmtss_create()
{
  return NULL;
}

#endif /* TSS_IBMTSS */
