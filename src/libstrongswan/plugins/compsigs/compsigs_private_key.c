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

#include "compsigs_private_key.h"
#include "compsigs_params.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>

#define ML_DSA_SEED_LEN 32

typedef struct private_private_key_t private_private_key_t;

/**
 * Private data
 */
struct private_private_key_t {

	/**
	 * Public interface
	 */
	private_key_t public;

	/**
	 * Parameters
	 */
	const compsigs_params_t *params;

	/**
	 * Underlying ML-DSA private key
	 */
	private_key_t *ml_dsa;

	/**
	 * Underlying traditional private key
	 */
	private_key_t *trad;

	/**
	 * Public key wrapper around the underlying public keys
	 */
	public_key_t *pubkey;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

/* defined in compsigs_public_key.c */
public_key_t *compsigs_public_key_create(const compsigs_params_t *params,
										 public_key_t *ml_dsa,
										 public_key_t *trad);

bool compsigs_get_mprime(const compsigs_params_t *params, chunk_t ctx,
						 chunk_t data, chunk_t *msg);

METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	pqc_params_t pqc_params, ml_dsa_params = {};
	const signature_params_t *trad;
	chunk_t mprime, sig_ml_dsa, sig_trad;
	bool ml_dsa_success, trad_success;

	if (key_type_from_signature_scheme(scheme) != this->params->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	if (!pqc_params_create(params, &pqc_params))
	{
		return FALSE;
	}
	if (pqc_params.deterministic)
	{
		DBG1(DBG_LIB, "signature scheme %N does not support deterministic "
			 "signatures", signature_scheme_names, scheme);
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

	ml_dsa_success = this->ml_dsa->sign(this->ml_dsa, this->params->ml_dsa_sig,
										&ml_dsa_params, mprime, &sig_ml_dsa);
	trad_success = this->trad->sign(this->trad, trad->scheme, trad->params,
									mprime, &sig_trad);
	chunk_free(&mprime);

	/* FIXME: not sure if there is much point in this, the draft says SHOULD, but
	 * the timing for the above operations will probably vary significantly if
	 * the ml-dsa or the traditional sig fails */
	if (ml_dsa_success & trad_success)
	{
		*signature = chunk_cat("mm", sig_ml_dsa, sig_trad);
		return TRUE;
	}
	/* FIXME: is this potentially timing-relevant? but see note above*/
	chunk_free(&sig_ml_dsa);
	chunk_free(&sig_trad);
	return FALSE;
}

METHOD(private_key_t, decrypt, bool,
	private_private_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "decryption scheme %N not supported for composite key",
		 encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_private_key_t *this)
{
	return BITS_PER_BYTE * get_public_key_size(this->params->type);
}

METHOD(private_key_t, get_type, key_type_t,
	private_private_key_t *this)
{
	return this->params->type;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_private_key_t *this)
{
	return this->pubkey->get_ref(this->pubkey);
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,	chunk_t *fp)
{
	return this->pubkey->get_fingerprint(this->pubkey, type, fp);
}

/**
 * Parses a PKCS#8 structure and returns the key type and wrapped key.
 */
static bool parse_pkcs8(chunk_t key, key_type_t *type, chunk_t *params,
						chunk_t *wrapped)
{
	chunk_t outer = key, inner, alg_id;
	int oid;

	if (asn1_unwrap(&outer, &outer) == ASN1_SEQUENCE &&
		asn1_unwrap(&outer, &inner) == ASN1_INTEGER &&
		asn1_parse_integer_uint64(inner) == 0 &&
		asn1_unwrap(&outer, &alg_id) == ASN1_SEQUENCE &&
		asn1_unwrap(&alg_id, &inner) == ASN1_OID &&
		(oid = asn1_known_oid(inner)) != OID_UNKNOWN &&
		asn1_unwrap(&outer, &inner) == ASN1_OCTET_STRING)
	{
		*type = key_type_from_oid(oid);
		if (params)
		{
			*params = alg_id;
		}
		*wrapped = inner;
		return TRUE;
	}
	return FALSE;
}

/**
 * Convert the given ECPrivateKey structure in one we can use i.e. with params
 * but no public key.
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 *
 * All implementations include the public key (OpenSSL only for generated
 * keys, not for private-only keys loaded from a composite).  And while
 * OpenSSL and wolfSSL include the parameters, Botan does not.  For the latter
 * we adopt them from the PKCS#8 wrapper.
 */
static chunk_t reconstruct_ecdsa(chunk_t params, chunk_t key)
{
	chunk_t outer = key, inner, priv, ec_params;

	if (asn1_unwrap(&outer, &outer) == ASN1_SEQUENCE &&
		asn1_unwrap(&outer, &inner) == ASN1_INTEGER &&
		asn1_parse_integer_uint64(inner) == 1 &&
		asn1_unwrap(&outer, &priv) == ASN1_OCTET_STRING)
	{
		if (asn1_unwrap(&outer, &ec_params) == ASN1_CONTEXT_C_0)
		{
			params = ec_params;
		}
		return asn1_wrap(ASN1_SEQUENCE, "csm",
						 ASN1_INTEGER_1,
						 asn1_wrap(ASN1_OCTET_STRING, "c", priv),
						 asn1_wrap(ASN1_CONTEXT_C_0, "c", params));
	}
	return chunk_clone(key);
}

/**
 * Unwraps the key from its PKCS#8 structure if that's the encoding we received.
 */
static chunk_t unwrap_pkcs8(chunk_t key, key_type_t type)
{
	key_type_t parsed_type;
	chunk_t params, unwrapped;

	if (parse_pkcs8(key, &parsed_type, &params, &unwrapped) &&
		parsed_type == type)
	{
		switch (type)
		{
			case KEY_ML_DSA_44:
			case KEY_ML_DSA_65:
			case KEY_ML_DSA_87:
				/* we only expect the seed-only format */
				/* FIXME: allow raw seed as workaround for Botan */
				if (unwrapped.len != ML_DSA_SEED_LEN &&
					asn1_unwrap(&unwrapped, &unwrapped) != ASN1_CONTEXT_S_0)
				{
					return chunk_empty;
				}
				break;
			case KEY_ED25519:
			case KEY_ED448:
				/* these are wrapped in another ASN1_OCTET_STRING */
				if (asn1_unwrap(&unwrapped, &unwrapped) != ASN1_OCTET_STRING)
				{
					return chunk_empty;
				}
				break;
			case KEY_ECDSA:
			{
				return reconstruct_ecdsa(params, unwrapped);
			}
			default:
				break;
		}
		return chunk_clone(unwrapped);
	}
	else
	{
		switch (type)
		{
			case KEY_ECDSA:
				return reconstruct_ecdsa(chunk_empty, key);
			default:
				break;
		}
	}
	return chunk_clone(key);
}

METHOD(private_key_t, get_encoding, bool,
	private_private_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	chunk_t enc_ml_dsa = chunk_empty, enc_trad = chunk_empty;
	bool success = TRUE;

	if (type != PRIVKEY_ASN1_DER &&
		type != PRIVKEY_PEM)
	{
		return FALSE;
	}

	if (!this->ml_dsa->get_encoding(this->ml_dsa, PRIVKEY_ASN1_DER,
									&enc_ml_dsa) ||
		!this->trad->get_encoding(this->trad, PRIVKEY_ASN1_DER,
								  &enc_trad))
	{
		chunk_clear(&enc_ml_dsa);
		return FALSE;
	}

	*encoding = asn1_wrap(ASN1_SEQUENCE, "cms",
					ASN1_INTEGER_0,
					asn1_algorithmIdentifier(key_type_to_oid(this->params->type)),
					asn1_wrap(ASN1_OCTET_STRING, "ss",
						unwrap_pkcs8(enc_ml_dsa, this->params->ml_dsa),
						unwrap_pkcs8(enc_trad, this->params->trad)));

	chunk_clear(&enc_ml_dsa);
	chunk_clear(&enc_trad);

	if (type == PRIVKEY_PEM)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
										NULL, encoding, CRED_PART_PRIV_ASN1_DER,
										asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(private_key_t, destroy, void,
	private_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->pubkey);
		DESTROY_IF(this->ml_dsa);
		DESTROY_IF(this->trad);
		free(this);
	}
}

/**
 * Create a public key wrapper around the underlying public keys.
 */
static public_key_t *create_public(private_private_key_t *this)
{
	public_key_t *ml_dsa, *trad;

	ml_dsa = this->ml_dsa->get_public_key(this->ml_dsa);
	trad = this->trad->get_public_key(this->trad);
	if (ml_dsa && trad)
	{
		return compsigs_public_key_create(this->params, ml_dsa, trad);
	}
	DESTROY_IF(ml_dsa);
	DESTROY_IF(trad);
	return NULL;
}

/**
 * Generic private constructor
 */
static private_key_t *create_instance(const compsigs_params_t *params,
									  private_key_t *ml_dsa,
									  private_key_t *trad)
{
	private_private_key_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.sign = _sign,
			.decrypt = _decrypt,
			.get_keysize = _get_keysize,
			.get_public_key = _get_public_key,
			.equals = private_key_equals,
			.belongs_to = private_key_belongs_to,
			.get_fingerprint = _get_fingerprint,
			.has_fingerprint = private_key_has_fingerprint,
			.get_encoding = _get_encoding,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.params = params,
		.ml_dsa = ml_dsa,
		.trad = trad,
		.ref = 1,
	);

	this->pubkey = create_public(this);
	if (!this->pubkey)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/*
 * Described in header
 */
private_key_t *compsigs_private_key_gen(key_type_t type, va_list args)
{
	const compsigs_params_t *params;
	private_key_t *ml_dsa, *trad;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* just ignore the key size */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	params = compsigs_params_get(type);
	if (!params)
	{
		return NULL;
	}

	/* pass a key size to skip constructors that load keys from blobs */
	ml_dsa = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, params->ml_dsa,
								BUILD_KEY_SIZE, 0, BUILD_END);
	if (!ml_dsa)
	{
		return NULL;
	}
	trad = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, params->trad,
							  BUILD_KEY_SIZE, params->trad_key_size, BUILD_END);
	if (!trad)
	{
		ml_dsa->destroy(ml_dsa);
		return NULL;
	}
	return create_instance(params, ml_dsa, trad);
}

/**
 * Wrap the given traditional private key in a PKCS#8 structure if necessary.
 */
chunk_t wrap_pkcs8(key_type_t type, chunk_t key)
{
	chunk_t encoding;

	switch (type)
	{
		case KEY_ED25519:
		case KEY_ED448:
			/* these two are encoded as raw private keys, note that the key is
			 * double wrapped in an octet string */
			encoding = asn1_wrap(ASN1_SEQUENCE, "cms",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(key_type_to_oid(type)),
							asn1_wrap(ASN1_OCTET_STRING, "s",
								asn1_simple_object(ASN1_OCTET_STRING, key)
							)
						);
			break;
		default:
			encoding = key;
			break;
	}
	return encoding;
}

/*
 * Described in header
 */
private_key_t *compsigs_private_key_load(key_type_t type, va_list args)
{
	chunk_t priv = chunk_empty, trad_encoding;
	const compsigs_params_t *params;
	private_key_t *ml_dsa, *trad;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				priv = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				parse_pkcs8(va_arg(args, chunk_t), &type, NULL, &priv);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	params = compsigs_params_get(type);
	if (priv.len <= ML_DSA_SEED_LEN || !params)
	{
		return NULL;
	}
	/* we just get the raw seed, our implementations should support that */
	ml_dsa = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
								params->ml_dsa, BUILD_BLOB,
								chunk_create(priv.ptr, ML_DSA_SEED_LEN),
								BUILD_END);
	if (!ml_dsa)
	{
		return NULL;
	}
	/* FIXME: maybe change the plugins so they can parse the encodings directly
	 * we could fix EdDSA by making the parsers use BUILD_BLOB instead of the
	 * BUILD_EDDSA_PRIV part and stripping the octet string wrapper beforehand
	 * same for the public keys */
	/* some encodings can't be parsed directly, so wrap them in PKCS#8 */
	priv = chunk_skip(priv, ML_DSA_SEED_LEN);
	trad_encoding = wrap_pkcs8(params->trad, priv);
	trad = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
							  params->trad, BUILD_BLOB_ASN1_DER,
							  trad_encoding, BUILD_END);
	if (trad_encoding.ptr != priv.ptr)
	{
		chunk_clear(&trad_encoding);
	}
	if (!trad)
	{
		ml_dsa->destroy(ml_dsa);
		return NULL;
	}
	return create_instance(params, ml_dsa, trad);
}
