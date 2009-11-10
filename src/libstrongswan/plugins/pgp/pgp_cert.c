/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "pgp_cert.h"
#include "pgp_utils.h"

#include <time.h>

#include <debug.h>

typedef struct private_pgp_cert_t private_pgp_cert_t;

/**
 * Private data of an pgp_cert_t object.
 */
struct private_pgp_cert_t {

	/**
	 * Implements pgp_cert_t interface.
	 */
	pgp_cert_t public;

	/**
	 * Public key of the certificate
	 */
	public_key_t *key;

	/**
	 * version of the public key
	 */
	u_int32_t version;

	/**
	 * creation time
	 */
	u_int32_t created;

	/**
	 * days the certificate is valid
	 */
	u_int32_t valid;

	/**
	 * userid of the certificate
	 */
	identification_t *user_id;

	/**
	 * v3 or v4 fingerprint of the PGP public key
	 */
	chunk_t fingerprint;

	/**
	 * full PGP encoding
	 */
	chunk_t encoding;

	/**
	 * reference counter
	 */
	refcount_t ref;
};


/**
 * Implementation of certificate_t.get_type
 */
static certificate_type_t get_type(private_pgp_cert_t *this)
{
	return CERT_GPG;
}

/**
 * Implementation of certificate_t.get_subject
 */
static identification_t* get_subject(private_pgp_cert_t *this)
{
	return this->user_id;
}

/**
 * Implementation of certificate_t.get_issuer
 */
static identification_t* get_issuer(private_pgp_cert_t *this)
{
	return this->user_id;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_subject(private_pgp_cert_t *this,
							  identification_t *subject)
{
	id_match_t match_user_id;

	match_user_id = this->user_id->matches(this->user_id, subject);
	if (match_user_id == ID_MATCH_NONE &&
		subject->get_type(subject) == ID_KEY_ID &&
        chunk_equals(this->fingerprint, subject->get_encoding(subject)))
	{
		return ID_MATCH_PERFECT;
	}
	return match_user_id;
}

/**
 * Implementation of certificate_t.has_subject.
 */
static id_match_t has_issuer(private_pgp_cert_t *this, identification_t *issuer)
{
	return ID_MATCH_NONE;
}

/**
 * Implementation of certificate_t.issued_by
 */
static bool issued_by(private_pgp_cert_t *this, certificate_t *issuer)
{
	/* TODO: check signature blobs for a valid signature */
	return FALSE;
}

/**
 * Implementation of certificate_t.get_public_key
 */
static public_key_t* get_public_key(private_pgp_cert_t *this)
{
	this->key->get_ref(this->key);
	return this->key;
}

/**
 * Implementation of certificate_t.get_ref
 */
static private_pgp_cert_t* get_ref(private_pgp_cert_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of certificate_t.get_validity.
 */
static bool get_validity(private_pgp_cert_t *this, time_t *when,
						 time_t *not_before, time_t *not_after)
{
	time_t t, until;

	if (when)
	{
		t = *when;
	}
	else
	{
		t = time(NULL);
	}
	if (not_before)
	{
		*not_before = this->created;
	}
	if (this->valid)
	{
		until = this->valid + this->created * 24 * 60 * 60;
	}
	else
	{
		/* Jan 19 03:14:07 UTC 2038 */
		until = TIME_32_BIT_SIGNED_MAX;
	}
	if (not_after)
	{
		*not_after = until;
	}
	return (t >= this->valid && t <= until);
}

/**
 * Implementation of certificate_t.is_newer.
 */
static bool is_newer(certificate_t *this, certificate_t *that)
{
	time_t this_update, that_update, now = time(NULL);
	bool new;

	this->get_validity(this, &now, &this_update, NULL);
	that->get_validity(that, &now, &that_update, NULL);
	new = this_update > that_update;
	DBG1("  certificate from %T is %s - existing certificate from %T %s",
				&this_update, FALSE, new ? "newer":"not newer",
				&that_update, FALSE, new ? "replaced":"retained");
	return new;
}

/**
 * Implementation of certificate_t.get_encoding.
 */
static chunk_t get_encoding(private_pgp_cert_t *this)
{
	return chunk_clone(this->encoding);
}

/**
 * Implementation of certificate_t.equals.
 */
static bool equals(private_pgp_cert_t *this, certificate_t *other)
{
	chunk_t encoding;
	bool equal;

	if (this == (private_pgp_cert_t*)other)
	{
		return TRUE;
	}
	if (other->get_type(other) != CERT_X509)
	{
		return FALSE;
	}
	if (other->equals == (void*)equals)
	{	/* skip allocation if we have the same implementation */
		return chunk_equals(this->encoding, ((private_pgp_cert_t*)other)->encoding);
	}
	encoding = other->get_encoding(other);
	equal = chunk_equals(this->encoding, encoding);
	free(encoding.ptr);
	return equal;
}

/**
 * Implementation of pgp_cert_t.destroy.
 */
static void destroy(private_pgp_cert_t *this)
{
	if (ref_put(&this->ref))
	{
		DESTROY_IF(this->key);
		DESTROY_IF(this->user_id);
		free(this->fingerprint.ptr);
		free(this->encoding.ptr);
		free(this);
	}
}

/**
 * Implementation of pgp_certificate_t.get_fingerprint.
 */
static chunk_t get_fingerprint(private_pgp_cert_t *this)
{
	return this->fingerprint;
}

/**
 * See header
 */
private_pgp_cert_t *create_empty()
{
	private_pgp_cert_t *this = malloc_thing(private_pgp_cert_t);

	this->public.interface.interface.get_type = (certificate_type_t (*) (certificate_t*))get_type;
	this->public.interface.interface.get_subject = (identification_t* (*) (certificate_t*))get_subject;
	this->public.interface.interface.get_issuer = (identification_t* (*) (certificate_t*))get_issuer;
	this->public.interface.interface.has_subject = (id_match_t (*) (certificate_t*, identification_t*))has_subject;
	this->public.interface.interface.has_issuer = (id_match_t (*) (certificate_t*, identification_t*))has_issuer;
	this->public.interface.interface.issued_by = (bool (*) (certificate_t*, certificate_t*))issued_by;
	this->public.interface.interface.get_public_key = (public_key_t* (*) (certificate_t*))get_public_key;
	this->public.interface.interface.get_validity = (bool (*) (certificate_t*, time_t*, time_t*, time_t*))get_validity;
	this->public.interface.interface.is_newer = (bool (*) (certificate_t*,certificate_t*))is_newer;
	this->public.interface.interface.get_encoding = (chunk_t (*) (certificate_t*))get_encoding;
	this->public.interface.interface.equals = (bool (*)(certificate_t*, certificate_t*))equals;
	this->public.interface.interface.get_ref = (certificate_t* (*)(certificate_t*))get_ref;
	this->public.interface.interface.destroy = (void (*)(certificate_t*))destroy;
	this->public.interface.get_fingerprint = (chunk_t (*)(pgp_certificate_t*))get_fingerprint;

	this->key = NULL;
	this->version = 0;
	this->created = 0;
	this->valid = 0;
	this->user_id = NULL;
	this->fingerprint = chunk_empty;
	this->encoding = chunk_empty;
	this->ref = 1;

	return this;
}

/**
 * Parse the public key packet of a PGP certificate
 */
static bool parse_public_key(private_pgp_cert_t *this, chunk_t packet)
{
	chunk_t pubkey_packet = packet;

	if (!pgp_read_scalar(&packet, 1, &this->version))
	{
		return FALSE;
	}
	switch (this->version)
	{
		case 3:
			if (!pgp_read_scalar(&packet, 4, &this->created) ||
				!pgp_read_scalar(&packet, 2, &this->valid))
			{
				return FALSE;
			}
			break;
		case 4:
			if (!pgp_read_scalar(&packet, 4, &this->created))
			{
				return FALSE;
			}
			break;
		default:
			DBG1("PGP packet version V%d not supported", this->version);
			return FALSE;
	}
	if (this->valid)
	{
		DBG2("L2 - created %T, valid %d days", &this->created, FALSE, this->valid);
	}
	else
	{
		DBG2("L2 - created %T, never expires", &this->created, FALSE);
	}
	DESTROY_IF(this->key);
	this->key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
									BUILD_BLOB_PGP, packet, BUILD_END);
	if (this->key == NULL)
	{
		return FALSE;
	}

	/* compute V4 or V3 fingerprint according to section 12.2 of RFC 4880 */
	if (this->version == 4)
	{
		chunk_t pubkey_packet_header = chunk_from_chars(
					0x99, pubkey_packet.len / 256, pubkey_packet.len % 256
				);
		hasher_t *hasher;

		hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (hasher == NULL)
		{
			DBG1("no SHA-1 hasher available");
			return FALSE;
		}
		hasher->allocate_hash(hasher, pubkey_packet_header, NULL);
		hasher->allocate_hash(hasher, pubkey_packet, &this->fingerprint);
		hasher->destroy(hasher);
		DBG2("L2 - v4 fingerprint %#B", &this->fingerprint);
	}
	else
	{
		/* V3 fingerprint is computed by public_key_t class */
		if (!this->key->get_fingerprint(this->key, KEY_ID_PGPV3,
										&this->fingerprint))
		{
			return FALSE;
		}
		this->fingerprint = chunk_clone(this->fingerprint);
		DBG2("L2 - v3 fingerprint %#B", &this->fingerprint);
	}
	return TRUE;
}

/**
 * Parse the signature packet of a PGP certificate
 */
static bool parse_signature(private_pgp_cert_t *this, chunk_t packet)
{
	u_int32_t version, len, type, created;

	if (!pgp_read_scalar(&packet, 1, &version))
	{
		return FALSE;
	}

	/* we parse only v3 or v4 signature packets */
	if (version != 3 && version != 4)
	{
		DBG2("L2 - v%d signature ignored", version);
		return TRUE;
	}
	if (version == 4)
	{
		if (!pgp_read_scalar(&packet, 1, &type))
		{
			return FALSE;
		}
		DBG2("L2 - v%d signature of type 0x%02x", version, type);
	}
	else
	{
		if (!pgp_read_scalar(&packet, 1, &len) || len != 5)
		{
			return FALSE;
		}
		if (!pgp_read_scalar(&packet, 1, &type) ||
			!pgp_read_scalar(&packet, 4, &created))
		{
			return FALSE;
		}
		DBG2("L2 - v3 signature of type 0x%02x, created %T", type,
												&created, FALSE);
	}
	/* TODO: parse and save signature to a list */
	return TRUE;
}

/**
 * Parse the userid packet of a PGP certificate
 */
static bool parse_user_id(private_pgp_cert_t *this, chunk_t packet)
{
	DESTROY_IF(this->user_id);
	this->user_id = identification_create_from_encoding(ID_KEY_ID, packet);
	DBG2("L2 - '%Y'", this->user_id);
	return TRUE;
}

/**
 * See header.
 */
pgp_cert_t *pgp_cert_load(certificate_type_t type, va_list args)
{
	chunk_t packet, blob = chunk_empty;
	pgp_packet_tag_t tag;
	private_pgp_cert_t *this;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_PGP:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = create_empty();
	this->encoding = chunk_clone(blob);
	while (blob.len)
	{
		if (!pgp_read_packet(&blob, &packet, &tag))
		{
			destroy(this);
			return NULL;
		}
		switch (tag)
		{
			case PGP_PKT_PUBLIC_KEY:
				if (!parse_public_key(this, packet))
				{
					destroy(this);
					return NULL;
				}
				break;
			case PGP_PKT_SIGNATURE:
				if (!parse_signature(this, packet))
				{
					destroy(this);
					return FALSE;
				}
				break;
			case PGP_PKT_USER_ID:
				if (!parse_user_id(this, packet))
				{
					destroy(this);
					return FALSE;
				}
				break;
			default:
				DBG1("ignoring %N packet in PGP certificate",
					 pgp_packet_tag_names, tag);
				break;
		}
	}
	if (this->key)
	{
		return &this->public;
	}
	destroy(this);
	return NULL;
}

