/*
 * Copyright (C) 2026 Duc Anh Luu
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

#include <library.h>
#include <utils/debug.h>
#include <plugins/plugin_feature.h>

/**
 * Input layout:
 *
 *   [0]     selects the ML-KEM parameter set and the operation
 *   [1..96] bytes returned by the RNG (keygen seeds d||z, encaps message m)
 *   [97..]  data received from the peer, zero-padded/truncated to the
 *           expected length (ciphertext, public key or ciphertext delta)
 */
#define RNG_LEN 96

/**
 * Coefficient modulus and length of the encoded polynomials in public keys
 */
#define Q 3329
#define POLY_LEN 384

static const struct {
	key_exchange_method_t method;
	size_t pk_len;
	size_t ct_len;
} methods[] = {
	{ ML_KEM_512,	800,	768 },
	{ ML_KEM_768,	1184,	1088 },
	{ ML_KEM_1024,	1568,	1568 },
};

enum {
	/* decapsulate a fuzzed ciphertext with a generated private key */
	OP_DECAPS,
	/* encapsulate a secret with a fuzzed public key as is */
	OP_ENCAPS_RAW,
	/* same, but reduce all coefficients modulo q so the key is valid */
	OP_ENCAPS_VALID,
	/* complete exchange, optionally with a modified ciphertext */
	OP_ROUNDTRIP,
	OP_MAX,
};

/**
 * Deterministic randomness taken from the fuzzer input, returns zeros once
 * it's exhausted
 */
static chunk_t rng_data;

METHOD(rng_t, get_bytes, bool,
	rng_t *this, size_t len, uint8_t *buffer)
{
	size_t take = min(len, rng_data.len);

	memcpy(buffer, rng_data.ptr, take);
	memset(buffer + take, 0, len - take);
	rng_data = chunk_skip(rng_data, take);
	return TRUE;
}

METHOD(rng_t, allocate_bytes, bool,
	rng_t *this, size_t len, chunk_t *chunk)
{
	*chunk = chunk_alloc(len);
	return get_bytes(this, len, chunk->ptr);
}

METHOD(rng_t, destroy, void,
	rng_t *this)
{
	free(this);
}

static rng_t *fuzz_rng_create(rng_quality_t quality)
{
	rng_t *this;

	INIT(this,
		.get_bytes = _get_bytes,
		.allocate_bytes = _allocate_bytes,
		.destroy = _destroy,
	);
	return this;
}

/**
 * Copy the given data to a buffer of exactly the given length
 */
static chunk_t fit(chunk_t data, size_t len)
{
	chunk_t fitted = chunk_alloc(len);

	memset(fitted.ptr, 0, len);
	memcpy(fitted.ptr, data.ptr, min(len, data.len));
	return fitted;
}

/**
 * Reduce the 12-bit coefficients of an encoded public key modulo q
 */
static void reduce_public_key(chunk_t public)
{
	uint16_t a, b;
	size_t i;

	for (i = 0; i + 3 <= public.len - 32; i += 3)
	{
		a = (public.ptr[i] | (public.ptr[i+1] << 8)) & 0xfff;
		b = (public.ptr[i+1] >> 4) | (public.ptr[i+2] << 4);
		a %= Q;
		b %= Q;
		public.ptr[i] = a;
		public.ptr[i+1] = (a >> 8) | (b << 4);
		public.ptr[i+2] = b >> 4;
	}
}

static void decaps(key_exchange_method_t method, chunk_t ciphertext)
{
	key_exchange_t *i;
	chunk_t public, secret;

	i = lib->crypto->create_ke(lib->crypto, method);
	if (i && i->get_public_key(i, &public))
	{
		chunk_free(&public);
		if (i->set_public_key(i, ciphertext) &&
			i->get_shared_secret(i, &secret))
		{
			chunk_clear(&secret);
		}
	}
	DESTROY_IF(i);
}

static void encaps(key_exchange_method_t method, chunk_t public)
{
	key_exchange_t *r;
	chunk_t ciphertext, secret;

	r = lib->crypto->create_ke(lib->crypto, method);
	if (r && r->set_public_key(r, public) &&
		r->get_public_key(r, &ciphertext))
	{
		chunk_free(&ciphertext);
		if (r->get_shared_secret(r, &secret))
		{
			chunk_clear(&secret);
		}
	}
	DESTROY_IF(r);
}

static void roundtrip(key_exchange_method_t method, chunk_t delta)
{
	key_exchange_t *i, *r;
	chunk_t public = chunk_empty, ciphertext = chunk_empty;
	chunk_t si = chunk_empty, sr = chunk_empty;
	bool modified = FALSE;
	size_t n;

	i = lib->crypto->create_ke(lib->crypto, method);
	r = lib->crypto->create_ke(lib->crypto, method);
	if (!i || !r)
	{
		DESTROY_IF(i);
		DESTROY_IF(r);
		return;
	}
	if (!i->get_public_key(i, &public) ||
		!r->set_public_key(r, public) ||
		!r->get_public_key(r, &ciphertext) ||
		!r->get_shared_secret(r, &sr))
	{
		/* generated keys must always be accepted */
		abort();
	}
	for (n = 0; n < ciphertext.len; n++)
	{
		ciphertext.ptr[n] ^= delta.ptr[n];
		modified |= delta.ptr[n] != 0;
	}
	if (!i->set_public_key(i, ciphertext) ||
		!i->get_shared_secret(i, &si))
	{
		abort();
	}
	/* implicit rejection must yield a different secret for any modification */
	if (chunk_equals(si, sr) == modified)
	{
		abort();
	}
	chunk_free(&public);
	chunk_free(&ciphertext);
	chunk_clear(&si);
	chunk_clear(&sr);
	i->destroy(i);
	r->destroy(r);
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	plugin_feature_t features[] = {
		PLUGIN_REGISTER(RNG, fuzz_rng_create),
			PLUGIN_PROVIDE(RNG, RNG_STRONG),
	};
	chunk_t data, peer;
	int m, op;

	if (len < 1)
	{
		return 0;
	}

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ml_kem");
	lib->plugins->add_static_features(lib->plugins, "fuzz-rng", features,
									  countof(features), TRUE, NULL, NULL);
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	data = chunk_create((u_char*)buf, len);
	m = data.ptr[0] % countof(methods);
	op = (data.ptr[0] / countof(methods)) % OP_MAX;
	data = chunk_skip(data, 1);
	rng_data = chunk_create(data.ptr, min(data.len, RNG_LEN));
	data = chunk_skip(data, RNG_LEN);

	switch (op)
	{
		case OP_DECAPS:
			peer = fit(data, methods[m].ct_len);
			decaps(methods[m].method, peer);
			break;
		case OP_ENCAPS_RAW:
		case OP_ENCAPS_VALID:
			peer = fit(data, methods[m].pk_len);
			if (op == OP_ENCAPS_VALID)
			{
				reduce_public_key(peer);
			}
			encaps(methods[m].method, peer);
			break;
		case OP_ROUNDTRIP:
		default:
			peer = fit(data, methods[m].ct_len);
			roundtrip(methods[m].method, peer);
			break;
	}
	chunk_free(&peer);

	lib->plugins->unload(lib->plugins);
	library_deinit();
	return 0;
}
