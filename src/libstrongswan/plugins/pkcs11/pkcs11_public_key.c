/*
 * Copyright (C) 2011-2015 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2024 Andreas Steffen
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

#include "pkcs11_public_key.h"

#include "pkcs11.h"
#include "pkcs11_private_key.h"
#include "pkcs11_manager.h"

#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <utils/debug.h>

typedef struct private_pkcs11_public_key_t private_pkcs11_public_key_t;

/**
 * Private data of an pkcs11_public_key_t object.
 */
struct private_pkcs11_public_key_t {

	/**
	 * Public pkcs11_public_key_t interface.
	 */
	pkcs11_public_key_t public;

	/**
	 * Type of the key
	 */
	key_type_t type;

	/**
	 * Key size in bits
	 */
	size_t k;

	/**
	 * PKCS#11 library this key uses
	 */
	pkcs11_library_t *lib;

	/**
	 * Slot the token is in
	 */
	CK_SLOT_ID slot;

	/**
	 * Session we use
	 */
	CK_SESSION_HANDLE session;

	/**
	 * Object handle to the key
	 */
	CK_OBJECT_HANDLE object;

	/**
	 * References to this key
	 */
	refcount_t ref;
};

/**
 * Helper function that returns the base point order length in bits of the
 * given named curve.
 *
 * Currently only a subset of defined curves is supported (namely the 5 curves
 * over Fp recommended by NIST). IKEv2 only supports 3 out of these.
 *
 * 0 is returned if the given curve is not supported.
 */
static size_t basepoint_order_len(int oid)
{
	switch (oid)
	{
		case OID_PRIME192V1:
			return 192;
		case OID_SECP224R1:
			return 224;
		case OID_PRIME256V1:
			return 256;
		case OID_SECP384R1:
			return 384;
		case OID_SECP521R1:
			return 521;
		default:
			return 0;
	}
}

/**
 * Parses the given ecParameters (ASN.1) and returns the key length.
 */
static bool keylen_from_ecparams(chunk_t ecparams, size_t *keylen)
{
	if (!asn1_parse_simple_object(&ecparams, ASN1_OID, 0, "named curve"))
	{
		return FALSE;
	}
	*keylen = basepoint_order_len(asn1_known_oid(ecparams));
	return *keylen > 0;
}

/**
 * Determine the key length from the parameters and prepare the ECPoint from
 * the given input.
 * Memory for ecpoint is allocated.
 */
static bool parse_ecdsa_public_key(chunk_t blob, chunk_t params,
								   chunk_t *ecpoint, size_t *keylen)
{
	if (!blob.len || !params.len || !keylen_from_ecparams(params, keylen))
	{
		return FALSE;
	}

	/* the correct way to encode an EC_POINT in PKCS#11 is as
	 * ASN.1 octet string */
	*ecpoint = asn1_wrap(ASN1_OCTET_STRING, "c", blob);
	return TRUE;
}


METHOD(public_key_t, get_type, key_type_t,
	private_pkcs11_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, get_keysize, int,
	private_pkcs11_public_key_t *this)
{
	return this->k;
}

METHOD(public_key_t, verify, bool,
	private_pkcs11_public_key_t *this, signature_scheme_t scheme, void *params,
	chunk_t data, chunk_t sig)
{
	CK_MECHANISM_PTR mechanism;
	CK_SESSION_HANDLE session;
	CK_RV rv;
	hash_algorithm_t hash_alg;
	chunk_t hash = chunk_empty, parse, r, s;
	size_t len;
	bool success = FALSE;

	mechanism = pkcs11_signature_scheme_to_mech(this->lib, this->slot, scheme,
												params, this->type, this->k,
												&hash_alg);
	if (!mechanism)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
			 signature_scheme_names, scheme);
		goto end;
	}
	switch (scheme)
	{
		case SIGN_ECDSA_WITH_SHA1_DER:
		case SIGN_ECDSA_WITH_SHA256_DER:
		case SIGN_ECDSA_WITH_SHA384_DER:
		case SIGN_ECDSA_WITH_SHA512_DER:
			/* PKCS#11 expects the ECDSA signatures as simple concatenation of
			 * r and s, so unwrap the ASN.1 encoded sequence */
			parse = sig;
			if (asn1_unwrap(&parse, &parse) != ASN1_SEQUENCE ||
				asn1_unwrap(&parse, &r) != ASN1_INTEGER ||
				asn1_unwrap(&parse, &s) != ASN1_INTEGER)
			{
				goto end;
			}
			r = chunk_skip_zero(r);
			s = chunk_skip_zero(s);
			len = (get_keysize(this) + 7) / 8;
			if (r.len > len || s.len > len)
			{
				goto end;
			}
			/* concatenate r and s (forced to the defined length) */
			sig = chunk_alloca(2*len);
			memset(sig.ptr, 0, sig.len);
			memcpy(sig.ptr + (len - r.len), r.ptr, r.len);
			memcpy(sig.ptr + len + (len - s.len), s.ptr, s.len);
			break;
		case SIGN_ML_DSA_44:
		case SIGN_ML_DSA_65:
		case SIGN_ML_DSA_87:
			/* don't skip zero-bytes for these */
			break;
		default:
			sig = chunk_skip_zero(sig);
			break;
	}
	rv = this->lib->f->C_OpenSession(this->slot, CKF_SERIAL_SESSION, NULL, NULL,
									 &session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
		goto end;
	}
	rv = this->lib->f->C_VerifyInit(session, mechanism, this->object);
	if (rv != CKR_OK)
	{
		this->lib->f->C_CloseSession(session);
		DBG1(DBG_LIB, "C_VerifyInit() failed: %N", ck_rv_names, rv);
		goto end;
	}
	if (hash_alg != HASH_UNKNOWN)
	{
		hasher_t *hasher;

		hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
		if (!hasher || !hasher->allocate_hash(hasher, data, &hash))
		{
			DESTROY_IF(hasher);
			this->lib->f->C_CloseSession(session);
			goto end;
		}
		hasher->destroy(hasher);
		switch (scheme)
		{
			case SIGN_RSA_EMSA_PKCS1_SHA1:
			case SIGN_RSA_EMSA_PKCS1_SHA2_256:
			case SIGN_RSA_EMSA_PKCS1_SHA2_384:
			case SIGN_RSA_EMSA_PKCS1_SHA2_512:
				/* encode PKCS#1 digestInfo if the token does not support it */
				hash = asn1_wrap(ASN1_SEQUENCE, "mm",
								 asn1_algorithmIdentifier(
									hasher_algorithm_to_oid(hash_alg)),
								 asn1_wrap(ASN1_OCTET_STRING, "m", hash));
				break;
			default:
				break;
		}
		data = hash;
	}
	rv = this->lib->f->C_Verify(session, data.ptr, data.len, sig.ptr, sig.len);
	this->lib->f->C_CloseSession(session);
	chunk_free(&hash);
	if (rv != CKR_OK)
	{
		DBG1(DBG_LIB, "C_Verify() failed: %N", ck_rv_names, rv);
		goto end;
	}
	success = TRUE;

end:
	if (mechanism)
	{
		free(mechanism->pParameter);
	}
	free(mechanism);
	return success;
}

METHOD(public_key_t, encrypt, bool,
	private_pkcs11_public_key_t *this, encryption_scheme_t scheme,
	void *params, chunk_t plain, chunk_t *crypt)
{
	CK_MECHANISM_PTR mechanism;
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR buf;
	CK_ULONG len;
	CK_RV rv;

	mechanism = pkcs11_encryption_scheme_to_mech(scheme);
	if (!mechanism)
	{
		DBG1(DBG_LIB, "encryption scheme %N not supported",
			 encryption_scheme_names, scheme);
		return FALSE;
	}
	rv = this->lib->f->C_OpenSession(this->slot, CKF_SERIAL_SESSION, NULL, NULL,
									 &session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	rv = this->lib->f->C_EncryptInit(session, mechanism, this->object);
	if (rv != CKR_OK)
	{
		this->lib->f->C_CloseSession(session);
		DBG1(DBG_LIB, "C_EncryptInit() failed: %N", ck_rv_names, rv);
		return FALSE;
	}
	len = (get_keysize(this) + 7) / 8;
	buf = malloc(len);
	rv = this->lib->f->C_Encrypt(session, plain.ptr, plain.len, buf, &len);
	this->lib->f->C_CloseSession(session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_LIB, "C_Encrypt() failed: %N", ck_rv_names, rv);
		free(buf);
		return FALSE;
	}
	*crypt = chunk_create(buf, len);
	return TRUE;
}

/**
 * Encode ECDSA key using a given encoding type
 */
static bool encode_ecdsa(private_pkcs11_public_key_t *this,
						 cred_encoding_type_t type, chunk_t *encoding)
{
	enumerator_t *enumerator;
	bool success = FALSE;
	CK_ATTRIBUTE attr[] = {
		{CKA_EC_PARAMS, NULL, 0},
		{CKA_EC_POINT, NULL, 0},
	};

	if (type != PUBKEY_SPKI_ASN1_DER && type != PUBKEY_PEM)
	{
		return FALSE;
	}

	enumerator = this->lib->create_object_attr_enumerator(this->lib,
							this->session, this->object, attr, countof(attr));
	if (enumerator && enumerator->enumerate(enumerator, NULL) &&
		attr[0].ulValueLen > 0 && attr[1].ulValueLen > 0)
	{
		chunk_t ecparams, ecpoint;
		ecparams = chunk_create(attr[0].pValue, attr[0].ulValueLen);
		ecpoint = chunk_create(attr[1].pValue, attr[1].ulValueLen);
		*encoding = public_key_info_encode(ecpoint, OID_EC_PUBLICKEY,
										   &ecparams);
		success = TRUE;
		if (type == PUBKEY_PEM)
		{
			chunk_t asn1 = *encoding;
			success = lib->encoding->encode(lib->encoding, PUBKEY_PEM,
							NULL, encoding, CRED_PART_ECDSA_PUB_ASN1_DER,
							asn1, CRED_PART_END);
			chunk_clear(&asn1);
		}
	}
	DESTROY_IF(enumerator);
	return success;
}

/**
 * Encode a public key stored in a CKA_VALUE using a given encoding type
 */
static bool encode_cka_value(private_pkcs11_public_key_t *this,
							 cred_encoding_type_t type, chunk_t *encoding)
{
	chunk_t pubkey, asn1;
	bool success;

	if (!this->lib->get_ck_attribute(this->lib, this->session, this->object,
									 CKA_VALUE, &pubkey))
	{
		return FALSE;
	}
	asn1 = public_key_info_encode(pubkey, key_type_to_oid(this->type), NULL);
	chunk_free(&pubkey);

	if (type == PUBKEY_SPKI_ASN1_DER)
	{
		*encoding = asn1;
		return TRUE;
	}
	success = lib->encoding->encode(lib->encoding, type, NULL, encoding,
									CRED_PART_PUB_ASN1_DER, asn1,
									CRED_PART_END);
	chunk_free(&asn1);
	return success;
}

/**
 * Compute fingerprint of a key stored in the given attribute type
 */
static bool fingerprint_key(private_pkcs11_public_key_t *this,
							CK_ATTRIBUTE_TYPE attr_type,
							cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t asn1;

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			if (!this->lib->get_ck_attribute(this->lib, this->session,
											 this->object, attr_type, &asn1))
			{
				return FALSE;
			}
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			switch (attr_type)
			{
				case CKA_EC_POINT:
					if (!encode_ecdsa(this, PUBKEY_SPKI_ASN1_DER, &asn1))
					{
						return FALSE;
					}
					break;
				case CKA_VALUE:
					if (!encode_cka_value(this, PUBKEY_SPKI_ASN1_DER, &asn1))
					{
						return FALSE;
					}
					break;
				default:
					return FALSE;
			}
			break;
		default:
			return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, asn1, fp))
	{
		DESTROY_IF(hasher);
		chunk_clear(&asn1);
		return FALSE;
	}
	hasher->destroy(hasher);
	chunk_clear(&asn1);
	lib->encoding->cache(lib->encoding, type, this, fp);
	return TRUE;
}

/**
 * Encode RSA key using a given encoding type
 */
static bool encode_rsa(private_pkcs11_public_key_t *this,
					cred_encoding_type_t type, void *cache, chunk_t *encoding)
{
	enumerator_t *enumerator;
	bool success = FALSE;
	CK_ATTRIBUTE attr[] = {
		{CKA_MODULUS, NULL, 0},
		{CKA_PUBLIC_EXPONENT, NULL, 0},
	};

	enumerator = this->lib->create_object_attr_enumerator(this->lib,
							this->session, this->object, attr, countof(attr));
	if (enumerator && enumerator->enumerate(enumerator, NULL) &&
		attr[0].ulValueLen > 0 && attr[1].ulValueLen > 0)
	{
		chunk_t n, e;
		/* some tokens/libraries add unnecessary 0x00 prefixes */
		n = chunk_skip_zero(chunk_create(attr[0].pValue, attr[0].ulValueLen));
		if (n.ptr[0] & 0x80)
		{	/* add leading 0x00, encoders might expect it in two's complement */
			n = chunk_cata("cc", chunk_from_chars(0x00), n);
		}
		e = chunk_skip_zero(chunk_create(attr[1].pValue, attr[1].ulValueLen));
		if (e.ptr[0] & 0x80)
		{
			e = chunk_cata("cc", chunk_from_chars(0x00), e);
		}
		success = lib->encoding->encode(lib->encoding, type, cache, encoding,
			CRED_PART_RSA_MODULUS, n, CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
	}
	DESTROY_IF(enumerator);
	return success;
}

METHOD(public_key_t, get_encoding, bool,
	private_pkcs11_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (this->type)
	{
		case KEY_RSA:
			return encode_rsa(this, type, NULL, encoding);
		case KEY_ECDSA:
			return encode_ecdsa(this, type, encoding);
		case KEY_ML_DSA_44:
		case KEY_ML_DSA_65:
		case KEY_ML_DSA_87:
			return encode_cka_value(this, type, encoding);
		default:
			return FALSE;
	}
}

METHOD(public_key_t, get_fingerprint, bool,
	private_pkcs11_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	switch (this->type)
	{
		case KEY_RSA:
			return encode_rsa(this, type, this, fp);
		case KEY_ECDSA:
			return fingerprint_key(this, CKA_EC_POINT, type, fp);
		case KEY_ML_DSA_44:
		case KEY_ML_DSA_65:
		case KEY_ML_DSA_87:
			return fingerprint_key(this, CKA_VALUE, type, fp);
		default:
			return FALSE;
	}
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_pkcs11_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_pkcs11_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		this->lib->f->C_CloseSession(this->session);
		free(this);
	}
}

/**
 * Create an empty PKCS#11 public key
 */
static private_pkcs11_public_key_t *create(key_type_t type, size_t k,
							pkcs11_library_t *p11, CK_SLOT_ID slot,
							CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	private_pkcs11_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.type = type,
		.k = k,
		.lib = p11,
		.slot = slot,
		.session = session,
		.object = object,
		.ref = 1,
	);

	return this;
}

/**
 * Find a key object, including PKCS11 library and slot
 */
static private_pkcs11_public_key_t* find_key(key_type_t type, size_t keylen,
											 CK_ATTRIBUTE_PTR tmpl, int count)
{
	private_pkcs11_public_key_t *this = NULL;
	pkcs11_manager_t *manager;
	enumerator_t *enumerator, *keys;
	pkcs11_library_t *p11;
	CK_SLOT_ID slot;

	manager = lib->get(lib, "pkcs11-manager");
	if (!manager)
	{
		return NULL;
	}

	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		CK_OBJECT_HANDLE object;
		CK_SESSION_HANDLE session;
		CK_RV rv;

		rv = p11->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
								   &session);
		if (rv != CKR_OK)
		{
			DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
			continue;
		}
		keys = p11->create_object_enumerator(p11, session, tmpl, count,
											 NULL, 0);
		if (keys->enumerate(keys, &object))
		{
			this = create(type, keylen, p11, slot, session, object);
			keys->destroy(keys);
			break;
		}
		keys->destroy(keys);
		p11->f->C_CloseSession(session);
	}
	enumerator->destroy(enumerator);
	return this;
}

/**
 * Find an RSA key object
 */
static private_pkcs11_public_key_t* find_rsa_key(chunk_t n, chunk_t e,
												 size_t keylen)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_RSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_MODULUS, n.ptr, n.len},
		{CKA_PUBLIC_EXPONENT, e.ptr, e.len},
	};
	return find_key(KEY_RSA, keylen, tmpl, countof(tmpl));
}

/**
 * Find an ECDSA key object
 */
static private_pkcs11_public_key_t* find_ecdsa_key(chunk_t ecparams,
												   chunk_t ecpoint,
												   size_t keylen)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_ECDSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_EC_PARAMS, ecparams.ptr, ecparams.len},
		{CKA_EC_POINT, ecpoint.ptr, ecpoint.len},
	};
	return find_key(KEY_ECDSA, keylen, tmpl, countof(tmpl));
}

/**
 * Find an ECDSA key object
 */
static private_pkcs11_public_key_t* find_ml_dsa_key(key_type_t key_type,
										CK_ML_DSA_PARAMETER_SET_TYPE param_set,
										chunk_t value)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_ML_DSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_PARAMETER_SET, &param_set, sizeof(param_set)},
		{CKA_VALUE, value.ptr, value.len},
	};
	return find_key(key_type, value.len * 8, tmpl, countof(tmpl));
}

/**
 * Create a key object in a suitable token session
 */
static private_pkcs11_public_key_t* create_key(key_type_t type, size_t keylen,
								CK_MECHANISM_TYPE_PTR mechanisms, int mcount,
								CK_ATTRIBUTE_PTR tmpl, int count)
{
	private_pkcs11_public_key_t *this = NULL;
	pkcs11_manager_t *manager;
	enumerator_t *enumerator, *mechs;
	pkcs11_library_t *p11;
	CK_SLOT_ID slot;

	manager = lib->get(lib, "pkcs11-manager");
	if (!manager)
	{
		return NULL;
	}

	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &slot))
	{
		CK_MECHANISM_TYPE mech;
		CK_MECHANISM_INFO info;
		CK_OBJECT_HANDLE object;
		CK_SESSION_HANDLE session;
		CK_RV rv;

		mechs = p11->create_mechanism_enumerator(p11, slot);
		while (mechs->enumerate(mechs, &mech, &info))
		{
			bool found = FALSE;
			int i;
			if (!(info.flags & CKF_VERIFY))
			{
				continue;
			}
			for (i = 0; i < mcount; i++)
			{
				if (mechanisms[i] == mech)
				{
					found = TRUE;
					break;
				}
			}
			if (!found)
			{
				continue;
			}
			rv = p11->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
									   &session);
			if (rv != CKR_OK)
			{
				DBG1(DBG_CFG, "opening PKCS#11 session failed: %N",
					 ck_rv_names, rv);
				continue;
			}
			rv = p11->f->C_CreateObject(session, tmpl, count, &object);
			if (rv == CKR_OK)
			{
				this = create(type, keylen, p11, slot, session, object);
				DBG2(DBG_CFG, "created %N public key on token '%s':%d ",
					 key_type_names, type, p11->get_name(p11), slot);
			}
			else
			{
				DBG1(DBG_CFG, "creating %N public key on token '%s':%d "
					 "failed: %N", key_type_names, type, p11->get_name(p11),
					 slot, ck_rv_names, rv);
				p11->f->C_CloseSession(session);
			}
			break;
		}
		mechs->destroy(mechs);
		if (this)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return this;
}

/**
 * Create an RSA key object in a suitable token session
 */
static private_pkcs11_public_key_t* create_rsa_key(chunk_t n, chunk_t e,
												   size_t keylen)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_RSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_MODULUS, n.ptr, n.len},
		{CKA_PUBLIC_EXPONENT, e.ptr, e.len},
	};
	CK_MECHANISM_TYPE mechs[] = {
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
		CKM_MD5_RSA_PKCS,
	};
	return create_key(KEY_RSA, keylen, mechs, countof(mechs), tmpl,
					  countof(tmpl));
}

/**
 * Create an ECDSA key object in a suitable token session
 */
static private_pkcs11_public_key_t* create_ecdsa_key(chunk_t ecparams,
													 chunk_t ecpoint,
													 size_t keylen)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_ECDSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_EC_PARAMS, ecparams.ptr, ecparams.len},
		{CKA_EC_POINT, ecpoint.ptr, ecpoint.len},
	};
	CK_MECHANISM_TYPE mechs[] = {
		CKM_ECDSA,
		CKM_ECDSA_SHA1,
	};
	return create_key(KEY_ECDSA, keylen, mechs,
					  countof(mechs), tmpl, countof(tmpl));
}

/**
 * Create an ML-DSA key object in a suitable token session
 */
static private_pkcs11_public_key_t* create_ml_dsa_key(key_type_t key_type,
										CK_ML_DSA_PARAMETER_SET_TYPE param_set,
										chunk_t value)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_ML_DSA;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_PARAMETER_SET, &param_set, sizeof(param_set)},
		{CKA_VALUE, value.ptr, value.len},
	};
	CK_MECHANISM_TYPE mechs[] = {
		CKM_ML_DSA,
	};
	return create_key(key_type, value.len * 8, mechs,
					  countof(mechs), tmpl, countof(tmpl));
}

/**
 * See header
 */
pkcs11_public_key_t *pkcs11_public_key_load(key_type_t type, va_list args)
{
	private_pkcs11_public_key_t *this;
	chunk_t n, e, blob, pkcs1, params;
	key_type_t parsed;
	size_t keylen = 0;

	n = e = blob = params = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				pkcs1 = va_arg(args, chunk_t);
				parsed = public_key_info_decode(pkcs1, &blob, &params);
				if (type != KEY_ANY && parsed != type)
				{
					return NULL;
				}
				type = parsed;
				continue;
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (type == KEY_RSA && e.ptr && n.ptr)
	{
		if (n.len && n.ptr[0] == 0)
		{	/* trim leading zero byte in modulus */
			n = chunk_skip(n, 1);
		}
		keylen = n.len * 8;
		this = find_rsa_key(n, e, keylen);
		if (this)
		{
			return &this->public;
		}
		this = create_rsa_key(n, e, keylen);
		if (this)
		{
			return &this->public;
		}
	}
	else if (blob.ptr)
	{
		switch (type)
		{
			case KEY_ECDSA:
			{
				chunk_t ecpoint = chunk_empty;

				if (!lib->settings->get_bool(lib->settings,
								"%s.plugins.pkcs11.use_ecc", FALSE, lib->ns))
				{
					return NULL;
				}
				if (parse_ecdsa_public_key(blob, params, &ecpoint, &keylen))
				{
					this = find_ecdsa_key(params, ecpoint, keylen);
					if (!this)
					{
						this = create_ecdsa_key(params, ecpoint, keylen);
					}
					chunk_free(&ecpoint);
					if (this)
					{
						return &this->public;
					}
				}
				break;
			}
			case KEY_ML_DSA_44:
			case KEY_ML_DSA_65:
			case KEY_ML_DSA_87:
			{
				CK_ML_DSA_PARAMETER_SET_TYPE param_set = CKP_ML_DSA_44;

				if (blob.len != get_public_key_size(type))
				{
					return NULL;
				}
				if (type == KEY_ML_DSA_65)
				{
					param_set = CKP_ML_DSA_65;
				}
				else if (type == KEY_ML_DSA_87)
				{
					param_set = CKP_ML_DSA_87;
				}
				this = find_ml_dsa_key(type, param_set, blob);
				if (!this)
				{
					this = create_ml_dsa_key(type, param_set, blob);
				}
				if (this)
				{
					return &this->public;
				}
				break;
			}
			default:
				break;
		}
	}
	return NULL;
}

static private_pkcs11_public_key_t *find_key_by_keyid(pkcs11_library_t *p11,
												int slot, key_type_t key_type,
												chunk_t keyid)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_ID, keyid.ptr, keyid.len},
		{CKA_KEY_TYPE, &type, sizeof(type)},
	};
	CK_OBJECT_HANDLE object;
	CK_ULONG param_set = 0;
	CK_ATTRIBUTE attr[] = {
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_PARAMETER_SET, &param_set, sizeof(param_set)},
	};
	CK_SESSION_HANDLE session;
	CK_RV rv;
	enumerator_t *enumerator;
	int count = countof(tmpl);
	size_t keylen = 0;

	switch (key_type)
	{
		case KEY_RSA:
			type = CKK_RSA;
			break;
		case KEY_ECDSA:
			type = CKK_ECDSA;
			break;
		case KEY_ML_DSA_44:
		case KEY_ML_DSA_65:
		case KEY_ML_DSA_87:
			type = CKK_ML_DSA;
			break;
		default:
			/* don't specify key type on KEY_ANY */
			count--;
			break;
	}

	rv = p11->f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening public key session on '%s':%d failed: %N",
			 p11->get_name(p11), slot, ck_rv_names, rv);
		return NULL;
	}

	enumerator = p11->create_object_enumerator(p11, session, tmpl, count, attr,
											   countof(attr));
	if (enumerator->enumerate(enumerator, &object) &&
		attr[0].ulValueLen != CK_UNAVAILABLE_INFORMATION)
	{
		switch (type)
		{
			case CKK_ECDSA:
			{
				chunk_t ecparams;
				if (p11->get_ck_attribute(p11, session, object, CKA_EC_PARAMS,
										  &ecparams) &&
					keylen_from_ecparams(ecparams, &keylen))
				{
					chunk_free(&ecparams);
					key_type = KEY_ECDSA;
				}
				break;
			}
			case CKK_RSA:
			{
				chunk_t n;
				if (p11->get_ck_attribute(p11, session, object, CKA_MODULUS,
										  &n) && n.len > 0)
				{
					keylen = n.len * 8;
					chunk_free(&n);
					key_type = KEY_RSA;
				}
				break;
			}
			case CKK_ML_DSA:
			{
				if (attr[1].ulValueLen != CK_UNAVAILABLE_INFORMATION)
				{
					switch (param_set)
					{
						case CKP_ML_DSA_44:
							key_type = KEY_ML_DSA_44;
							keylen = get_public_key_size(key_type) * 8;
							break;
						case CKP_ML_DSA_65:
							key_type = KEY_ML_DSA_65;
							keylen = get_public_key_size(key_type) * 8;
							break;
						case CKP_ML_DSA_87:
							key_type = KEY_ML_DSA_87;
							keylen = get_public_key_size(key_type) * 8;
							break;
					}
				}
				break;
			}
			default:
				DBG1(DBG_CFG, "PKCS#11 key type %d not supported", type);
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (keylen)
	{
		return create(key_type, keylen, p11, slot, session, object);
	}
	p11->f->C_CloseSession(session);
	return NULL;
}

/**
 * See header.
 */
public_key_t *pkcs11_public_key_connect(pkcs11_library_t *p11, int slot,
										key_type_t type, chunk_t keyid)
{
	private_pkcs11_public_key_t *this;

	this = find_key_by_keyid(p11, slot, type, keyid);
	if (!this)
	{
		return NULL;
	}
	return &this->public.key;
}
