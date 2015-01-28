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

#include "cga_trust.h"

#include <library.h>
#include <utils/debug.h>


typedef struct private_cga_trust_t private_cga_trust_t;
typedef struct private_cga_anchor_t private_cga_anchor_t;

/**
 * Private data of a cga_trust_t object.
 */
struct private_cga_trust_t {

	/**
	 * Public interface for this credential set.
	 */
	cga_trust_t public;

	/**
	 * Trust anchor identity
	 */
	identification_t *ta;
};

/**
 * Private data of trust anchor certificate.
 */
struct private_cga_anchor_t {

	/**
	 * Implements certificate_t.
	 */
	certificate_t public;

	/**
	 * Trust anchor identity
	 */
	identification_t *ta;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(certificate_t, get_type, certificate_type_t,
	private_cga_anchor_t *this)
{
	return CERT_CGA_PARAMS;
}

METHOD(certificate_t, get_ta, identification_t*,
	private_cga_anchor_t *this)
{
	return this->ta;
}

METHOD(certificate_t, has_ta, id_match_t,
	private_cga_anchor_t *this, identification_t *id)
{
	return this->ta->matches(this->ta, id);
}

METHOD(certificate_t, issued_by, bool,
	private_cga_anchor_t *this, certificate_t *issuer,
	signature_scheme_t *schemep)
{
	if (&this->public == issuer)
	{
		if (schemep)
		{
			*schemep = SIGN_CGA_SHA1;
		}
		return TRUE;
	}
	return FALSE;
}

METHOD(certificate_t, get_public_key, public_key_t*,
	private_cga_anchor_t *this)
{
	return NULL;
}

METHOD(certificate_t, get_ref, certificate_t*,
	private_cga_anchor_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(certificate_t, get_validity, bool,
	private_cga_anchor_t *this, time_t *when, time_t *not_before,
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
	private_cga_anchor_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	return FALSE;
}

METHOD(certificate_t, equals, bool,
	private_cga_anchor_t *this, certificate_t *other)
{
	return &this->public == other;
}

METHOD(certificate_t, anchor_destroy, void,
	private_cga_anchor_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this);
	}
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_cga_trust_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	private_cga_anchor_t *anchor;

	if (cert != CERT_CGA_PARAMS)
	{
		return enumerator_create_empty();
	}
	if (id && !id->matches(id, this->ta))
	{
		return enumerator_create_empty();
	}

	INIT(anchor,
		.public = {
			.get_type = _get_type,
			.get_subject = _get_ta,
			.get_issuer = _get_ta,
			.has_subject = _has_ta,
			.has_issuer = _has_ta,
			.issued_by = _issued_by,
			.get_public_key = _get_public_key,
			.get_validity = _get_validity,
			.get_encoding = _get_encoding,
			.equals = _equals,
			.get_ref = _get_ref,
			.destroy = _anchor_destroy,
		},
		.ref = 1,
		.ta = this->ta,
	);

	return enumerator_create_single(anchor, (void*)anchor_destroy);
}

METHOD(cga_trust_t, destroy, void,
	private_cga_trust_t *this)
{
	this->ta->destroy(this->ta);
	free(this);
}

/**
 * See header.
 */
cga_trust_t *cga_trust_create()
{
	private_cga_trust_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = (void*)enumerator_create_empty,
				.create_private_enumerator = (void*)enumerator_create_empty,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)enumerator_create_empty,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
		.ta = identification_create_from_string("CGA Trust Anchor"),
	);

	return &this->public;
}
