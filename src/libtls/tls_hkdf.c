/*
 * Copyright (C) 2020 Tobias Brunner
 * Copyright (C) 2020 Pascal Knecht
 * Copyright (C) 2020 Méline Sieber
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

#include "tls_hkdf.h"

#include <bio/bio_writer.h>
#include <crypto/prf_plus.h>

typedef struct private_tls_hkdf_t private_tls_hkdf_t;

typedef enum hkdf_phase {
	HKDF_PHASE_0,
	HKDF_PHASE_1,
	HKDF_PHASE_2,
	HKDF_PHASE_3,
} hkdf_phase;

struct private_tls_hkdf_t {

	/**
	 * Public tls_hkdf_t interface.
	 */
	struct tls_hkdf_t public;

	/**
	 * Phase we are in.
	 */
	hkdf_phase phase;

	/**
	 * Pseudorandom function used.
	 */
	prf_t *prf;

	/**
	 * Hasher used.
	 */
	hasher_t *hasher;

	/**
	 * (EC)DHE as IKM to switch from phase 1 to phase 2
	 */
	chunk_t shared_secret;

	/**
	 * PSK used.
	 */
	chunk_t psk;

	/**
	 * PRK used.
	 */
	chunk_t prk;

	/**
	 * OKM used.
	 */
	chunk_t okm;

	/**
	 * Current implementation needs a copy of derived secrets to calculate the
	 * proper finished key.
	 */
	chunk_t client_traffic_secret;
	chunk_t server_traffic_secret;
};

static char *hkdf_labels[] = {
	"tls13 ext binder",
	"tls13 res binder",
	"tls13 c e traffic",
	"tls13 e exp master",
	"tls13 c hs traffic",
	"tls13 s hs traffic",
	"tls13 c ap traffic",
	"tls13 s ap traffic",
	"tls13 exp master",
	"tls13 res master",
};

/**
 * Step 1: Extract, as defined in RFC 5869, section 2.2:
 * HKDF-Extract(salt, IKM) -> PRK
 */
static bool extract(private_tls_hkdf_t *this, chunk_t salt, chunk_t ikm,
					chunk_t *prk)
{
	if (!this->prf->set_key(this->prf, salt))
	{
		DBG1(DBG_TLS, "unable to set PRF secret to salt");
		return FALSE;
	}
	chunk_clear(prk);
	if(!this->prf->allocate_bytes(this->prf, ikm, prk))
	{
		DBG1(DBG_TLS, "unable to allocate PRF result");
		return FALSE;
	}

	DBG4(DBG_TLS, "PRK: %B", prk);

	return TRUE;
}

/**
 * Step 2: Expand as defined in RFC 5869, section 2.3:
 * HKDF-Expand(PRK, info, L) -> OKM
 */
static bool expand(private_tls_hkdf_t *this, chunk_t prk, chunk_t info,
				   size_t length, chunk_t *okm)
{
	prf_plus_t *prf_plus;

	if (!this->prf->set_key(this->prf, prk))
	{
		DBG1(DBG_TLS, "unable to set PRF secret to PRK");
		return FALSE;
	}
	prf_plus = prf_plus_create(this->prf, TRUE, info);
	chunk_clear(okm);
	if (!prf_plus || !prf_plus->allocate_bytes(prf_plus, length, okm))
	{
		DBG1(DBG_TLS, "unable to allocate PRF+ result");
		DESTROY_IF(prf_plus);
		chunk_clear(okm);
		return FALSE;
	}
	prf_plus->destroy(prf_plus);

	DBG4(DBG_TLS, "OKM: %B", okm);

	return TRUE;
}

/**
 * Expand-Label as defined in RFC 8446, section 7.1:
 * HKDF-Expand-Label(Secret, Label, Context, Length) -> OKM
 */
static bool expand_label(private_tls_hkdf_t *this, chunk_t secret,
						 chunk_t label, chunk_t context, uint16_t length,
						 chunk_t *key)
{
	bool success;

	if (label.len < 7 || label.len > 255 || context.len > 255)
	{
		return FALSE;
	}

	/* HKDFLabel as defined in RFC 8446, section 7.1 */
	bio_writer_t *writer = bio_writer_create(0);
	writer->write_uint16(writer, length);
	writer->write_data8(writer, label);
	writer->write_data8(writer, context);

	success = expand(this, secret, writer->get_buf(writer), length, key);
	writer->destroy(writer);
	return success;
}

/**
 * Derive-Secret as defined in RFC 8446, section 7.1:
 * Derive-Secret(Secret, Label, Message) -> OKM
 */
static bool derive_secret(private_tls_hkdf_t *this, chunk_t label,
						  chunk_t messages)
{
	chunk_t context;
	bool success;

	if (!this->hasher->allocate_hash(this->hasher, messages, &context))
	{
		return FALSE;
	}

	success = expand_label(this, this->prk, label, context,
						   this->hasher->get_hash_size(this->hasher),
						   &this->okm);
	chunk_free(&context);
	return success;
}

/**
 * Move to phase 1 (Early Secret)
 *
 *            0
 *            |
 *            v
 *  PSK ->  HKDF-Extract = Early Secret
 *            |
 *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *            |                     = binder_key
 *            |
 *            +-----> Derive-Secret(., "c e traffic", ClientHello)
 *            |                     = client_early_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "e exp master", ClientHello)
 *            |                     = early_exporter_master_secret
 *            v
 */
static bool move_to_phase_1(private_tls_hkdf_t *this)
{
	chunk_t salt_zero, psk = this->psk;

	switch (this->phase)
	{
		case HKDF_PHASE_0:
			salt_zero = chunk_alloca(this->hasher->get_hash_size(this->hasher));
			chunk_copy_pad(salt_zero, chunk_empty, 0);
			if (!psk.ptr)
			{
				psk = salt_zero;
			}
			if (!extract(this, salt_zero, psk, &this->prk))
			{
				DBG1(DBG_TLS, "unable to extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_1;
			return TRUE;
		case HKDF_PHASE_1:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

/**
 * Move to phase 2 (Handshake Secret)
 *
 *      Derive-Secret(., "derived", "")
 *            |
 *            v
 *  (EC)DHE -> HKDF-Extract = Handshake Secret
 *            |
 *            +-----> Derive-Secret(., "c hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = client_handshake_traffic_secret
 *            |
 *            +-----> Derive-Secret(., "s hs traffic",
 *            |                     ClientHello...ServerHello)
 *            |                     = server_handshake_traffic_secret
 *            v
 */
static bool move_to_phase_2(private_tls_hkdf_t *this)
{
	chunk_t derived;

	switch (this->phase)
	{
		case HKDF_PHASE_0:
			if (!move_to_phase_1(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 1");
				return FALSE;
			}
			/* fall-through */
		case HKDF_PHASE_1:
			derived = chunk_from_str("tls13 derived");
			if (!derive_secret(this, derived, chunk_empty))
			{
				DBG1(DBG_TLS, "unable to derive secret");
				return FALSE;
			}

			if (!this->shared_secret.ptr)
			{
				DBG1(DBG_TLS, "no shared secret set");
				return FALSE;
			}

			if (!extract(this, this->okm, this->shared_secret, &this->prk))
			{
				DBG1(DBG_TLS, "unable extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_2;
			return TRUE;
		case HKDF_PHASE_2:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

/**
 * Move to phase 3 (Master Secret)
 *
 *      Derive-Secret(., "derived", "")
 *            |
 *            v
 *  0 -> HKDF-Extract = Master Secret
 *            |
 *            +-----> Derive-Secret(., "c ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = client_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "s ap traffic",
 *            |                     ClientHello...server Finished)
 *            |                     = server_application_traffic_secret_0
 *            |
 *            +-----> Derive-Secret(., "exp master",
 *            |                     ClientHello...server Finished)
 *            |                     = exporter_master_secret
 *            |
 *            +-----> Derive-Secret(., "res master",
 *                                  ClientHello...client Finished)
 *                                  = resumption_master_secret
 */
static bool move_to_phase_3(private_tls_hkdf_t *this)
{
	chunk_t derived, ikm_zero;

	switch (this->phase)
	{
		case HKDF_PHASE_0:
		case HKDF_PHASE_1:
			if (!move_to_phase_2(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 2");
				return FALSE;
			}
			/* fall-through */
		case HKDF_PHASE_2:
			/* prepare okm for next extract */
			derived = chunk_from_str("tls13 derived");
			if (!derive_secret(this, derived, chunk_empty))
			{
				DBG1(DBG_TLS, "unable to derive secret");
				return FALSE;
			}

			ikm_zero = chunk_alloca(this->hasher->get_hash_size(this->hasher));
			chunk_copy_pad(ikm_zero, chunk_empty, 0);
			if (!extract(this, this->okm, ikm_zero, &this->prk))
			{
				DBG1(DBG_TLS, "unable extract PRK");
				return FALSE;
			}
			this->phase = HKDF_PHASE_3;
			return TRUE;
		case HKDF_PHASE_3:
			return TRUE;
		default:
			DBG1(DBG_TLS, "invalid HKDF phase");
			return FALSE;
	}
}

METHOD(tls_hkdf_t, set_shared_secret, void,
	private_tls_hkdf_t *this, chunk_t shared_secret)
{
	this->shared_secret = chunk_clone(shared_secret);
}

METHOD(tls_hkdf_t, generate_secret, bool,
	private_tls_hkdf_t *this, tls_hkdf_label_t label, chunk_t messages,
	chunk_t *secret)
{
	switch (label)
	{
		case TLS_HKDF_EXT_BINDER:
		case TLS_HKDF_RES_BINDER:
		case TLS_HKDF_C_E_TRAFFIC:
		case TLS_HKDF_E_EXP_MASTER:
			if (!move_to_phase_1(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 1");
				return FALSE;
			}
			break;
		case TLS_HKDF_C_HS_TRAFFIC:
		case TLS_HKDF_S_HS_TRAFFIC:
			if (!move_to_phase_2(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 2");
				return FALSE;
			}
			break;
		case TLS_HKDF_C_AP_TRAFFIC:
		case TLS_HKDF_S_AP_TRAFFIC:
		case TLS_HKDF_EXP_MASTER:
		case TLS_HKDF_RES_MASTER:
			if (!move_to_phase_3(this))
			{
				DBG1(DBG_TLS, "unable to move to phase 3");
				return FALSE;
			}
			break;
		default:
			DBG1(DBG_TLS, "invalid HKDF label");
			return FALSE;
	}

	if (!derive_secret(this, chunk_from_str(hkdf_labels[label]), messages))
	{
		DBG1(DBG_TLS, "unable to derive secret");
		return FALSE;
	}

	if (label == TLS_HKDF_C_HS_TRAFFIC || label == TLS_HKDF_C_AP_TRAFFIC)
	{
		chunk_clear(&this->client_traffic_secret);
		this->client_traffic_secret = chunk_clone(this->okm);
	}

	if (label == TLS_HKDF_S_HS_TRAFFIC || label == TLS_HKDF_S_AP_TRAFFIC)
	{
		chunk_clear(&this->server_traffic_secret);
		this->server_traffic_secret = chunk_clone(this->okm);
	}

	if (secret)
	{
		*secret = chunk_clone(this->okm);
	}
	return TRUE;
}

/**
 * Derive keys/IVs from the current traffic secrets.
 */
static bool get_shared_label_keys(private_tls_hkdf_t *this, chunk_t label,
								  bool is_server, size_t length, chunk_t *key)
{
	chunk_t result = chunk_empty, secret;

	secret = is_server ? this->server_traffic_secret
					   : this->client_traffic_secret;

	if (!expand_label(this, secret, label, chunk_empty, length, &result))
	{
		DBG1(DBG_TLS, "unable to derive labeled secret");
		chunk_clear(&result);
		return FALSE;
	}

	if (key)
	{
		*key = result;
	}
	else
	{
		chunk_clear(&result);
	}
	return TRUE;
}

METHOD(tls_hkdf_t, derive_key, bool,
	private_tls_hkdf_t *this, bool is_server, size_t length, chunk_t *key)
{
	return get_shared_label_keys(this, chunk_from_str("tls13 key"), is_server,
								 length, key);
}

METHOD(tls_hkdf_t, derive_iv, bool,
	private_tls_hkdf_t *this, bool is_server, size_t length, chunk_t *iv)
{
	return get_shared_label_keys(this, chunk_from_str("tls13 iv"), is_server,
								 length, iv);
}

METHOD(tls_hkdf_t, derive_finished, bool,
	private_tls_hkdf_t *this, bool is_server, chunk_t *finished)
{
	return get_shared_label_keys(this, chunk_from_str("tls13 finished"),
								 is_server,
								 this->hasher->get_hash_size(this->hasher),
								 finished);
}

METHOD(tls_hkdf_t, allocate_bytes, bool,
	private_tls_hkdf_t *this, chunk_t key, chunk_t seed,
	chunk_t *out)
{
	return this->prf->set_key(this->prf, key) &&
		   this->prf->allocate_bytes(this->prf, seed, out);
}

METHOD(tls_hkdf_t, destroy, void,
	private_tls_hkdf_t *this)
{
	chunk_clear(&this->psk);
	chunk_clear(&this->prk);
	chunk_clear(&this->shared_secret);
	chunk_clear(&this->okm);
	chunk_clear(&this->client_traffic_secret);
	chunk_clear(&this->server_traffic_secret);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->hasher);
	free(this);
}

tls_hkdf_t *tls_hkdf_create(hash_algorithm_t hash_algorithm, chunk_t psk)
{
	private_tls_hkdf_t *this;
	pseudo_random_function_t prf_algorithm;

	switch (hash_algorithm)
	{
		case HASH_SHA256:
			prf_algorithm = PRF_HMAC_SHA2_256;
			break;
		case HASH_SHA384:
			prf_algorithm = PRF_HMAC_SHA2_384;
			break;
		default:
			DBG1(DBG_TLS, "unsupported hash algorithm %N", hash_algorithm_names,
				 hash_algorithm);
			return NULL;
	}

	INIT(this,
		.public = {
			.set_shared_secret = _set_shared_secret,
			.generate_secret = _generate_secret,
			.derive_key = _derive_key,
			.derive_iv = _derive_iv,
			.derive_finished = _derive_finished,
			.allocate_bytes = _allocate_bytes,
			.destroy = _destroy,
		},
		.phase = HKDF_PHASE_0,
		.psk = psk.ptr ? chunk_clone(psk) : chunk_empty,
		.prf = lib->crypto->create_prf(lib->crypto, prf_algorithm),
		.hasher = lib->crypto->create_hasher(lib->crypto, hash_algorithm),
	);

	if (!this->prf || !this->hasher)
	{
		if (!this->prf)
		{
			DBG1(DBG_TLS, "%N not supported", pseudo_random_function_names,
				 prf_algorithm);
		}
		if (!this->hasher)
		{
			DBG1(DBG_TLS, "%N not supported", hash_algorithm_names,
				 hash_algorithm);
		}
		DBG1(DBG_TLS, "unable to initialise HKDF");
		destroy(this);
		return NULL;
	}
	return &this->public;
}
