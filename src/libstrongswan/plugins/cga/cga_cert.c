/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include "cga_cert.h"

#include <errno.h>

#include <library.h>
#include <utils/debug.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <crypto/hashers/hasher.h>
#include <utils/identification.h>


typedef struct private_cga_cert_t private_cga_cert_t;

/**
 * Private data of a cga_cert_t object.
 */
struct private_cga_cert_t {

	/**
	 * Public interface for this certificate.
	 */
	cga_cert_t public;

	/**
	 * CGA parameters encoding
	 */
	chunk_t encoding;

	/**
	 * Wrapped public key
	 */
	public_key_t *public_key;

	/**
	 * CGA as ID_IPV6_ADDR identity, the certificate subject
	 */
	identification_t *cga;

	/**
	 * Certificate issuer, which is "CGA trust anchor"
	 */
	identification_t *anchor;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(certificate_t, get_type, certificate_type_t,
	private_cga_cert_t *this)
{
	return CERT_CGA_PARAMS;
}

METHOD(certificate_t, get_subject, identification_t*,
	private_cga_cert_t *this)
{
	return this->cga;
}

METHOD(certificate_t, get_issuer, identification_t*,
	private_cga_cert_t *this)
{
	return this->anchor;
}

METHOD(certificate_t, has_subject, id_match_t,
	private_cga_cert_t *this, identification_t *subject)
{
	return this->cga->matches(this->cga, subject);
}

METHOD(certificate_t, has_issuer, id_match_t,
	private_cga_cert_t *this, identification_t *issuer)
{
	return this->anchor->matches(this->anchor, issuer);
}

METHOD(certificate_t, issued_by, bool,
	private_cga_cert_t *this, certificate_t *issuer,
	signature_scheme_t *schemep)
{
	if (issuer->get_type(issuer) != CERT_CGA_PARAMS)
	{
		return FALSE;
	}
	if (!this->anchor->equals(this->anchor, issuer->get_subject(issuer)))
	{
		return FALSE;
	}
	/* any parsed CGA is valid */
	if (schemep)
	{
		*schemep = SIGN_CGA_SHA1;
	}
	return TRUE;
}

METHOD(certificate_t, get_public_key, public_key_t*,
	private_cga_cert_t *this)
{
	return this->public_key->get_ref(this->public_key);
}

METHOD(certificate_t, get_ref, certificate_t*,
	private_cga_cert_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
}

METHOD(certificate_t, get_validity, bool,
	private_cga_cert_t *this, time_t *when, time_t *not_before,
	time_t *not_after)
{
	if (not_before)
	{
		*not_before = UNDEFINED_TIME;
	}
	if (not_after)
	{
		*not_after = UNDEFINED_TIME;
	}
	return TRUE;
}

METHOD(certificate_t, get_encoding, bool,
	private_cga_cert_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	if (type == CERT_CGA_ENCODING)
	{
		*encoding = chunk_clone(this->encoding);
		return TRUE;
	}
	return FALSE;
}

METHOD(certificate_t, equals, bool,
	private_cga_cert_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;

	if (this == (private_cga_cert_t*)other)
	{
		return TRUE;
	}
	if (other->get_type(other) != CERT_CGA_PARAMS)
	{
		return FALSE;
	}
	if (other->equals == (void*)equals)
	{	/* same implementation */
		return chunk_equals(this->encoding,
							((private_cga_cert_t*)other)->encoding);
	}
	if (!other->get_encoding(other, CERT_CGA_ENCODING, &encoding))
	{
		return FALSE;
	}
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

METHOD(certificate_t, destroy, void,
	private_cga_cert_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this->encoding.ptr);
		DESTROY_IF(this->public_key);
		DESTROY_IF(this->cga);
		this->anchor->destroy(this->anchor);
		free(this);
	}
}

/**
 * Generic constructor
 */
static private_cga_cert_t* create()
{
	private_cga_cert_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_type = _get_type,
				.get_subject = _get_subject,
				.get_issuer = _get_issuer,
				.has_subject = _has_subject,
				.has_issuer = _has_issuer,
				.issued_by = _issued_by,
				.get_public_key = _get_public_key,
				.get_validity = _get_validity,
				.get_encoding = _get_encoding,
				.equals = _equals,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.anchor = identification_create_from_string("CGA Trust Anchor"),
		.ref = 1,
	);
	return this;
}

/**
 * CGA parameter encoding:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Modifier (16 octets)                     +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                    Subnet Prefix (8 octets)                   +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Collision Count|                                               |
 * +-+-+-+-+-+-+-+-+                                               |
 * |                                                               |
 * ~                  Public Key (variable length)                 ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~           Extension Fields (optional, variable length)        ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct __attribute__((packed)) {
	char modifier[16];
	char prefix[8];
	u_int8_t collision;
	char public_key[];
} cga_t;

/**
 * Parse CGA parameters and guess the CGA address
 */
static bool parse(private_cga_cert_t *this)
{
	char hash1[HASH_SIZE_SHA1], hash2[HASH_SIZE_SHA1], cga[16], zero[14] = {};
	hasher_t *hasher;
	chunk_t pubkey, modifier;
	size_t len;
	u_int sec;

	if (this->encoding.len <= offsetof(cga_t, public_key))
	{
		return FALSE;
	}
	if (this->encoding.ptr[offsetof(cga_t, collision)] > 2)
	{
		return FALSE;
	}
	pubkey = chunk_skip(this->encoding, offsetof(cga_t, public_key));
	len = asn1_length(&pubkey);
	if (len == ASN1_INVALID_LENGTH)
	{
		return FALSE;
	}
	/* re-add the tag length removed by asn1_length() */
	len += pubkey.ptr - (this->encoding.ptr + offsetof(cga_t, public_key));
	pubkey = chunk_create(this->encoding.ptr + offsetof(cga_t, public_key), len);
	this->public_key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY,
										  KEY_ANY, BUILD_BLOB,
										  pubkey, BUILD_END);
	if (!this->public_key)
	{
		return FALSE;
	}
	modifier = chunk_create(this->encoding.ptr, 16);

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		return FALSE;
	}
	if (!hasher->get_hash(hasher, this->encoding, hash1))
	{
		hasher->destroy(hasher);
		return FALSE;
	}

	/* set u/g bits to zero */
	hash1[0] &= ~0x03;
	/* Reconstruct a CGA from the parameters for the highest matching Sec
	 * parameter. We generate CGA parameters that have a unique CGA when
	 * reconstructed this way, but a ~1:2^16 probability exists that we pick a
	 * CGA with a higher Sec level for externally generated parameters. */
	for (sec = 7; sec <= 7; sec--)
	{
		hash1[0] &= ~(0xE0);
		hash1[0] |= sec << 5;

		if (!hasher->get_hash(hasher, modifier, NULL) ||
			!hasher->get_hash(hasher, chunk_create(zero, 9), NULL) ||
			!hasher->get_hash(hasher, pubkey, hash2))
		{
			hasher->destroy(hasher);
			return FALSE;
		}
		if (memeq(zero, hash2, sec * 2))
		{
			memcpy(cga, &this->encoding.ptr[offsetof(cga_t, prefix)], 8);
			memcpy(cga + 8, hash1, 8);
			this->cga = identification_create_from_encoding(ID_IPV6_ADDR,
														chunk_from_thing(cga));
			hasher->destroy(hasher);
			return TRUE;
		}
	}
	hasher->destroy(hasher);
	return FALSE;
}

/**
 * See header.
 */
cga_cert_t *cga_cert_load(certificate_type_t type, va_list args)
{
	chunk_t blob = chunk_empty, *map = NULL;
	private_cga_cert_t *cert;
	char *file = NULL;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_FROM_FILE:
				file = va_arg(args, char*);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (file)
	{
		map = chunk_map(file, FALSE);
		if (!map)
		{
			DBG1(DBG_LIB, "reading CGA file '%s' failed: %s",
				 file, strerror(errno));
			return NULL;
		}
	}
	cert = create();
	if (map)
	{
		cert->encoding = chunk_clone(*map);
		chunk_unmap(map);
	}
	else
	{
		cert->encoding = chunk_clone(blob);
	}
	if (!parse(cert))
	{
		destroy(cert);
		return NULL;
	}
	return &cert->public;
}

/**
 * Generate a a new CGA for the supplied parameters
 */
static bool generate(private_cga_cert_t *this, char *prefix, u_int sec)
{
	char modifier[16], zero[16] = {}, hash[HASH_SIZE_SHA1], cga[16];
	u_int8_t collision = 0;
	chunk_t pubkey;
	hasher_t *hasher;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FALSE;
	}
	if (!rng->get_bytes(rng, sizeof(modifier), modifier))
	{
		rng->destroy(rng);
		return FALSE;
	}
	rng->destroy(rng);
	if (!this->public_key->get_encoding(this->public_key,
										PUBKEY_SPKI_ASN1_DER, &pubkey))
	{
		return FALSE;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		free(pubkey.ptr);
		return FALSE;
	}
	do
	{
		chunk_increment(chunk_from_thing(modifier));
		if (!hasher->get_hash(hasher, chunk_from_thing(modifier), NULL) ||
			!hasher->get_hash(hasher, chunk_create(zero, 9), NULL) ||
			!hasher->get_hash(hasher, pubkey, hash))
		{
			hasher->destroy(hasher);
			free(pubkey.ptr);
			return FALSE;
		}
	}
	/* brute force until sec words are zero. We skip hashes that would comply
	 * to a higher Sec level: This makes CGAs unique when re-constructed from
	 * the CGA parameters if the highest matching Sec value is used during
	 * reconstruction. */
	while (!memeq(zero, hash, sec * 2) || memeq(zero, hash, (sec + 1) * 2));

	this->encoding = chunk_cat("cccm",
						chunk_from_thing(modifier), chunk_create(prefix, 8),
						chunk_from_thing(collision), pubkey);

	if (!hasher->get_hash(hasher, this->encoding, hash))
	{
		hasher->destroy(hasher);
		return FALSE;
	}
	hasher->destroy(hasher);

	/* write Sec parameter */
	hash[0] &= ~0xE0;
	hash[0] |= sec << 5;
	/* set u/g bits to zero */
	hash[0] &= ~0x03;

	memcpy(cga, prefix, 8);
	memcpy(cga + 8, hash, 8);

	this->cga = identification_create_from_encoding(ID_IPV6_ADDR,
													chunk_from_thing(cga));

	return TRUE;
}

/**
 * See header.
 */
cga_cert_t *cga_cert_gen(certificate_type_t type, va_list args)
{
	private_cga_cert_t *cert;
	public_key_t *public_key = NULL;
	chunk_t prefix = chunk_empty;
	int sec = 0;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_PUBLIC_KEY:
				public_key = va_arg(args, public_key_t*);
				continue;
			case BUILD_CGA_PREFIX:
				prefix = va_arg(args, chunk_t);
				continue;
			case BUILD_CGA_SEC:
				sec = va_arg(args, int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (sec < 0 || sec > 7 || prefix.len != 8 || !public_key)
	{
		DBG1(DBG_LIB, "invalid CGA parameters");
		return NULL;
	}
	cert = create();
	cert->public_key = public_key->get_ref(public_key);
	if (generate(cert, prefix.ptr, sec))
	{
		return &cert->public;
	}
	destroy(cert);
	return NULL;
}
