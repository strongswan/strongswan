/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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

#include "compsigs_public_key.h"
#include "compsigs_params.h"

#include <asn1/asn1.h>

#define COMPSIG_PREFIX "CompositeAlgorithmSignatures2025"

typedef struct private_public_key_t private_public_key_t;

/**
 * Private data
 */
struct private_public_key_t {

	/**
	 * Public interface
	 */
	public_key_t public;

	/**
	 * Parameters
	 */
	const compsigs_params_t *params;

	/**
	 * Underlying ML-DSA public key
	 */
	public_key_t *ml_dsa;

	/**
	 * Underlying traditional public key
	 */
	public_key_t *trad;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_public_key_t *this)
{
	return this->params->type;
}

/**
 * Generate M' from the given parameters.
 */
bool compsigs_get_mprime(const compsigs_params_t *params, chunk_t ctx,
						 chunk_t data, chunk_t *msg)
{
	hasher_t *hasher;
	xof_t *xof;
	chunk_t ph;

	if (params->pre_xof != XOF_UNDEFINED)
	{
		xof = lib->crypto->create_xof(lib->crypto, params->pre_xof);
		if (!xof || !xof->set_seed(xof, data) ||
			!xof->allocate_bytes(xof, params->xof_len, &ph))
		{
			DESTROY_IF(xof);
			return FALSE;
		}
		xof->destroy(xof);
	}
	else
	{
		hasher = lib->crypto->create_hasher(lib->crypto, params->pre_hash);
		if (!hasher || !hasher->allocate_hash(hasher, data, &ph))
		{
			DESTROY_IF(hasher);
			return FALSE;
		}
		hasher->destroy(hasher);
	}

	*msg = chunk_cat("cccm", chunk_from_str(COMPSIG_PREFIX),
					 chunk_from_str((char*)params->label), ctx, ph);
	return TRUE;
}

METHOD(public_key_t, verify, bool,
	private_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	pqc_params_t pqc_params, ml_dsa_params = {};
	const signature_params_t *trad;
	chunk_t mprime, sig_ml_dsa, sig_trad;

	if (key_type_from_signature_scheme(scheme) != this->params->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	if (signature.len <= this->params->ml_dsa_sig_len)
	{
		DBG1(DBG_LIB, "signature for %N too short",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	if (!pqc_params_create(params, &pqc_params))
	{
		return FALSE;
	}
	if (!compsigs_get_mprime(this->params, pqc_params.pre_ctx, data, &mprime))
	{
		chunk_free(&pqc_params.pre_ctx);
		return FALSE;
	}
	chunk_free(&pqc_params.pre_ctx);

	ml_dsa_params.ctx = chunk_from_str((char*)this->params->label);

	trad = &this->params->trad_sig;

	chunk_split(signature, "mm", this->params->ml_dsa_sig_len, &sig_ml_dsa,
				signature.len - this->params->ml_dsa_sig_len, &sig_trad);

	if (!this->ml_dsa->verify(this->ml_dsa, this->params->ml_dsa_sig,
							  &ml_dsa_params, mprime, sig_ml_dsa) ||
		!this->trad->verify(this->trad, trad->scheme, trad->params, mprime,
							sig_trad))
	{
		chunk_free(&mprime);
		return FALSE;
	}
	chunk_free(&mprime);
	return TRUE;
}

METHOD(public_key_t, encrypt_, bool,
	private_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported for composite key",
		 encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_public_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->params->type);
}

/**
 * Unwrap the raw key from its subjectPublicKeyInfo structure that we requested
 * from the underlying implementation.
 */
static chunk_t unwrap_spki(chunk_t key, key_type_t type)
{
	chunk_t outer = key, inner;

	if (asn1_unwrap(&outer, &outer) == ASN1_SEQUENCE &&
		asn1_unwrap(&outer, &inner) == ASN1_SEQUENCE &&
		asn1_unwrap(&inner, &inner) == ASN1_OID &&
		key_type_from_oid(asn1_known_oid(inner)) == type &&
		asn1_unwrap(&outer, &inner) == ASN1_BIT_STRING &&
		inner.len > 0 && *inner.ptr == 0)
	{
		return chunk_skip(inner, 1);
	}
	return chunk_empty;
}

/**
 * Generate a raw encoding of the public key data of the underlying keys.
 */
static bool get_raw_encoding(private_public_key_t *this, chunk_t *encoding)
{
	chunk_t enc_ml_dsa = chunk_empty, enc_trad = chunk_empty;

	if (!this->ml_dsa->get_encoding(this->ml_dsa, PUBKEY_SPKI_ASN1_DER,
									&enc_ml_dsa) ||
		!this->trad->get_encoding(this->trad, PUBKEY_SPKI_ASN1_DER,
								  &enc_trad))
	{
		chunk_free(&enc_ml_dsa);
		return FALSE;
	}

	*encoding = chunk_cat("cc",
						  unwrap_spki(enc_ml_dsa, this->params->ml_dsa),
						  unwrap_spki(enc_trad, this->params->trad));
	chunk_free(&enc_ml_dsa);
	chunk_free(&enc_trad);
	return TRUE;
}

/**
 * Generate two types of public key fingerprints.
 */
static bool compsigs_fingerprint(private_public_key_t *this,
								 cred_encoding_type_t type, chunk_t *fp)
{
	chunk_t raw, encoding;
	hasher_t *hasher;

	*fp = chunk_empty;

	if (!get_raw_encoding(this, &raw))
	{
		return FALSE;
	}

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			encoding = raw;
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			encoding = public_key_info_encode(raw,
									key_type_to_oid(this->params->type), NULL);
			chunk_free(&raw);
			break;
		default:
			chunk_free(&raw);
			return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, encoding, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported");
		DESTROY_IF(hasher);
		chunk_free(&encoding);
		return FALSE;
	}
	hasher->destroy(hasher);
	chunk_free(&encoding);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success = FALSE;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}

	success = compsigs_fingerprint(this, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}
	return success;
}


METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	chunk_t raw = chunk_empty;
	bool success = TRUE;

	if (!get_raw_encoding(this, &raw))
	{
		return FALSE;
	}

	*encoding = public_key_info_encode(raw, key_type_to_oid(this->params->type),
									   NULL);
	chunk_free(&raw);

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
										NULL, encoding, CRED_PART_PUB_ASN1_DER,
										asn1_encoding, CRED_PART_END);
		chunk_free(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(public_key_t, destroy, void,
	private_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		DESTROY_IF(this->ml_dsa);
		DESTROY_IF(this->trad);
		free(this);
	}
}

/**
 * Generic constructor also used by private key implementation
 */
public_key_t *compsigs_public_key_create(const compsigs_params_t *params,
										 public_key_t *ml_dsa,
										 public_key_t *trad)
{
	private_public_key_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.verify = _verify,
			.encrypt = _encrypt_,
			.get_keysize = _get_keysize,
			.equals = public_key_equals,
			.get_fingerprint = _get_fingerprint,
			.has_fingerprint = public_key_has_fingerprint,
			.get_encoding = _get_encoding,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.params = params,
		.ml_dsa = ml_dsa,
		.trad = trad,
		.ref = 1,
	);

	return &this->public;
}


/**
 * Wrap the given traditional public key in a subjectPublicKeyInfo structure if
 * necessary.
 */
static chunk_t wrap_spki(const compsigs_params_t *params, chunk_t key)
{
	chunk_t encoding;

	switch (params->trad)
	{
		case KEY_ECDSA:
		{
			/* these are encoded as raw ECPoint, we need to identify the curve
			 * and wrap them */
			chunk_t curve = asn1_build_known_oid(params->trad_ecc_curve);
			encoding = public_key_info_encode(key,
										key_type_to_oid(params->trad), &curve);
			chunk_free(&curve);
			break;
		}
		case KEY_ED25519:
		case KEY_ED448:
			/* these two are encoded as raw public keys */
			encoding = public_key_info_encode(key,
										key_type_to_oid(params->trad), NULL);
			break;
		default:
			encoding = key;
			break;
	}
	return encoding;
}

/**
 * Make sure the given traditional public key conforms to the parameter set.
 */
bool compsigs_check_trad(const compsigs_params_t *params, public_key_t *key)
{
	if (key->get_keysize(key) != params->trad_key_size)
	{
		return FALSE;
	}

	if (params->trad == KEY_ECDSA)
	{
		chunk_t curve, oid;
		int known;

		if (!key->get_encoding(key, PUBKEY_ECDSA_CURVE_DER, &curve))
		{
			return FALSE;
		}
		oid = curve;
		if (asn1_unwrap(&oid, &oid) != ASN1_OID)
		{
			oid = curve;
		}
		known = asn1_known_oid(oid);
		if (params->trad_ecc_curve != known)
		{
			chunk_free(&curve);
			return FALSE;
		}
		chunk_free(&curve);
	}
	return TRUE;
}

/*
 * Described in header
 */
public_key_t *compsigs_public_key_load(key_type_t type, va_list args)
{
	chunk_t blob = chunk_empty, trad_encoding;
	const compsigs_params_t *params;
	public_key_t *ml_dsa, *trad;
	key_type_t parsed;
	size_t pubkey_len;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				parsed = public_key_info_decode(va_arg(args, chunk_t), &blob,
												NULL);
				if (type != KEY_ANY && parsed != type)
				{
					return NULL;
				}
				type = parsed;
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	params = compsigs_params_get(type);
	if (!blob.len || !params)
	{
		return NULL;
	}
	pubkey_len = get_public_key_size(params->ml_dsa);
	if (blob.len <= pubkey_len)
	{
		return NULL;
	}
	ml_dsa = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, params->ml_dsa,
								BUILD_BLOB, chunk_create(blob.ptr, pubkey_len),
								BUILD_END);
	if (!ml_dsa)
	{
		return NULL;
	}
	/* some encodings can't be parsed directly, so wrap them in a SPKI struct */
	blob = chunk_skip(blob, pubkey_len);
	trad_encoding = wrap_spki(params, blob);
	trad = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, params->trad,
							  BUILD_BLOB_ASN1_DER, trad_encoding, BUILD_END);
	if (trad_encoding.ptr != blob.ptr)
	{
		chunk_free(&trad_encoding);
	}
	if (!trad || !compsigs_check_trad(params, trad))
	{
		ml_dsa->destroy(ml_dsa);
		DESTROY_IF(trad);
		return NULL;
	}
	return compsigs_public_key_create(params, ml_dsa, trad);
}
