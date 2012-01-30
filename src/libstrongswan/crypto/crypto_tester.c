/*
 * Copyright (C) 2009-2010 Martin Willi
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2010 revosec AG
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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <time.h>

#include "crypto_tester.h"

#include <debug.h>
#include <utils/linked_list.h>

typedef struct private_crypto_tester_t private_crypto_tester_t;

/**
 * Private data of an crypto_tester_t object.
 */
struct private_crypto_tester_t {

	/**
	 * Public crypto_tester_t interface.
	 */
	crypto_tester_t public;

	/**
	 * List of crypter test vectors
	 */
	linked_list_t *crypter;

	/**
	 * List of aead test vectors
	 */
	linked_list_t *aead;

	/**
	 * List of signer test vectors
	 */
	linked_list_t *signer;

	/**
	 * List of hasher test vectors
	 */
	linked_list_t *hasher;

	/**
	 * List of PRF test vectors
	 */
	linked_list_t *prf;

	/**
	 * List of RNG test vectors
	 */
	linked_list_t *rng;

	/**
	 * Is a test vector required to pass a test?
	 */
	bool required;

	/**
	 * should we run RNG_TRUE tests? Enough entropy?
	 */
	bool rng_true;

	/**
	 * time we test each algorithm
	 */
	int bench_time;

	/**
	 * size of buffer we use for benchmarking
	 */
	int bench_size;
};

/**
 * Get the name of a test vector, if available
 */
static const char* get_name(void *sym)
{
#ifdef HAVE_DLADDR
	Dl_info dli;

	if (dladdr(sym, &dli))
	{
		return dli.dli_sname;
	}
#endif
	return "unknown";
}

#ifdef CLOCK_THREAD_CPUTIME_ID

/**
 * Start a benchmark timer
 */
static void start_timing(struct timespec *start)
{
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, start);
}

/**
 * End a benchmark timer, return ms
 */
static u_int end_timing(struct timespec *start)
{
	struct timespec end;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	return (end.tv_nsec - start->tv_nsec) / 1000000 +
			(end.tv_sec - start->tv_sec) * 1000;
}

#else /* CLOCK_THREAD_CPUTIME_ID */

/* Make benchmarking a no-op if CLOCK_THREAD_CPUTIME_ID is not available */
#define start_timing(start) ((start)->tv_sec = 0, (start)->tv_nsec = 0)
#define end_timing(...) (this->bench_time)

#endif /* CLOCK_THREAD_CPUTIME_ID */

/**
 * Benchmark a crypter
 */
static u_int bench_crypter(private_crypto_tester_t *this,
	encryption_algorithm_t alg, crypter_constructor_t create)
{
	crypter_t *crypter;

	crypter = create(alg, 0);
	if (crypter)
	{
		char iv[crypter->get_iv_size(crypter)];
		char key[crypter->get_key_size(crypter)];
		chunk_t buf;
		struct timespec start;
		u_int runs;

		memset(iv, 0x56, sizeof(iv));
		memset(key, 0x12, sizeof(key));
		crypter->set_key(crypter, chunk_from_thing(key));

		buf = chunk_alloc(this->bench_size);
		memset(buf.ptr, 0x34, buf.len);

		runs = 0;
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			crypter->encrypt(crypter, buf, chunk_from_thing(iv), NULL);
			runs++;
			crypter->decrypt(crypter, buf, chunk_from_thing(iv), NULL);
			runs++;
		}
		free(buf.ptr);
		crypter->destroy(crypter);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_crypter, bool,
	private_crypto_tester_t *this, encryption_algorithm_t alg, size_t key_size,
	crypter_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	crypter_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	enumerator = this->crypter->create_enumerator(this->crypter);
	while (enumerator->enumerate(enumerator, &vector))
	{
		crypter_t *crypter;
		chunk_t key, plain, cipher, iv;

		if (vector->alg != alg)
		{
			continue;
		}
		if (key_size && key_size != vector->key_size)
		{	/* test only vectors with a specific key size, if key size given */
			continue;
		}
		crypter = create(alg, vector->key_size);
		if (!crypter)
		{
			DBG1(DBG_LIB, "%N[%s]: %u bit key size not supported",
				 encryption_algorithm_names, alg, plugin_name,
				 BITS_PER_BYTE * vector->key_size);
			failed = TRUE;
			continue;
		}

		failed = FALSE;
		tested++;

		key = chunk_create(vector->key, crypter->get_key_size(crypter));
		crypter->set_key(crypter, key);
		iv = chunk_create(vector->iv, crypter->get_iv_size(crypter));

		/* allocated encryption */
		plain = chunk_create(vector->plain, vector->len);
		crypter->encrypt(crypter, plain, iv, &cipher);
		if (!memeq(vector->cipher, cipher.ptr, cipher.len))
		{
			failed = TRUE;
		}
		/* inline decryption */
		crypter->decrypt(crypter, cipher, iv, NULL);
		if (!memeq(vector->plain, cipher.ptr, cipher.len))
		{
			failed = TRUE;
		}
		free(cipher.ptr);
		/* allocated decryption */
		cipher = chunk_create(vector->cipher, vector->len);
		crypter->decrypt(crypter, cipher, iv, &plain);
		if (!memeq(vector->plain, plain.ptr, plain.len))
		{
			failed = TRUE;
		}
		/* inline encryption */
		crypter->encrypt(crypter, plain, iv, NULL);
		if (!memeq(vector->cipher, plain.ptr, plain.len))
		{
			failed = TRUE;
		}
		free(plain.ptr);

		crypter->destroy(crypter);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 encryption_algorithm_names, alg, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		if (failed)
		{
			DBG1(DBG_LIB,"disable %N[%s]: no key size supported",
				 encryption_algorithm_names, alg, plugin_name);
			return FALSE;
		}
		else
		{
			DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
				 this->required ? "disabled" : "enabled ",
				 encryption_algorithm_names, alg, plugin_name);
			return !this->required;
		}
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_crypter(this, alg, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 encryption_algorithm_names, alg, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 encryption_algorithm_names, alg, plugin_name, tested);
		}
	}
	return !failed;
}

/**
 * Benchmark an aead transform
 */
static u_int bench_aead(private_crypto_tester_t *this,
	encryption_algorithm_t alg, aead_constructor_t create)
{
	aead_t *aead;

	aead = create(alg, 0);
	if (aead)
	{
		char iv[aead->get_iv_size(aead)];
		char key[aead->get_key_size(aead)];
		char assoc[4];
		chunk_t buf;
		struct timespec start;
		u_int runs;
		size_t icv;

		memset(iv, 0x56, sizeof(iv));
		memset(key, 0x12, sizeof(key));
		memset(assoc, 0x78, sizeof(assoc));
		aead->set_key(aead, chunk_from_thing(key));
		icv = aead->get_icv_size(aead);

		buf = chunk_alloc(this->bench_size + icv);
		memset(buf.ptr, 0x34, buf.len);
		buf.len -= icv;

		runs = 0;
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			aead->encrypt(aead, buf, chunk_from_thing(assoc),
						  chunk_from_thing(iv), NULL);
			runs += 2;
			aead->decrypt(aead, chunk_create(buf.ptr, buf.len + icv),
						  chunk_from_thing(assoc), chunk_from_thing(iv), NULL);
			runs += 2;
		}
		free(buf.ptr);
		aead->destroy(aead);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_aead, bool,
	private_crypto_tester_t *this, encryption_algorithm_t alg, size_t key_size,
	aead_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	aead_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	enumerator = this->aead->create_enumerator(this->aead);
	while (enumerator->enumerate(enumerator, &vector))
	{
		aead_t *aead;
		chunk_t key, plain, cipher, iv, assoc;
		size_t icv;

		if (vector->alg != alg)
		{
			continue;
		}
		if (key_size && key_size != vector->key_size)
		{	/* test only vectors with a specific key size, if key size given */
			continue;
		}
		aead = create(alg, vector->key_size);
		if (!aead)
		{
			DBG1(DBG_LIB, "%N[%s]: %u bit key size not supported",
				 encryption_algorithm_names, alg, plugin_name,
				 BITS_PER_BYTE * vector->key_size);
			failed = TRUE;
			continue;
		}

		failed = FALSE;
		tested++;

		key = chunk_create(vector->key, aead->get_key_size(aead));
		aead->set_key(aead, key);
		iv = chunk_create(vector->iv, aead->get_iv_size(aead));
		assoc = chunk_create(vector->adata, vector->alen);
		icv = aead->get_icv_size(aead);

		/* allocated encryption */
		plain = chunk_create(vector->plain, vector->len);
		aead->encrypt(aead, plain, assoc, iv, &cipher);
		if (!memeq(vector->cipher, cipher.ptr, cipher.len))
		{
			failed = TRUE;
		}
		/* inline decryption */
		if (!aead->decrypt(aead, cipher, assoc, iv, NULL))
		{
			failed = TRUE;
		}
		if (!memeq(vector->plain, cipher.ptr, cipher.len - icv))
		{
			failed = TRUE;
		}
		free(cipher.ptr);
		/* allocated decryption */
		cipher = chunk_create(vector->cipher, vector->len + icv);
		if (!aead->decrypt(aead, cipher, assoc, iv, &plain))
		{
			plain = chunk_empty;
			failed = TRUE;
		}
		else if (!memeq(vector->plain, plain.ptr, plain.len))
		{
			failed = TRUE;
		}
		plain.ptr = realloc(plain.ptr, plain.len + icv);
		/* inline encryption */
		aead->encrypt(aead, plain, assoc, iv, NULL);
		if (!memeq(vector->cipher, plain.ptr, plain.len + icv))
		{
			failed = TRUE;
		}
		free(plain.ptr);

		aead->destroy(aead);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 encryption_algorithm_names, alg, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		if (failed)
		{
			DBG1(DBG_LIB,"disable %N[%s]: no key size supported",
				 encryption_algorithm_names, alg, plugin_name);
			return FALSE;
		}
		else
		{
			DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
				 this->required ? "disabled" : "enabled ",
				 encryption_algorithm_names, alg, plugin_name);
			return !this->required;
		}
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_aead(this, alg, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 encryption_algorithm_names, alg, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 encryption_algorithm_names, alg, plugin_name, tested);
		}
	}
	return !failed;
}

/**
 * Benchmark a signer
 */
static u_int bench_signer(private_crypto_tester_t *this,
	encryption_algorithm_t alg, signer_constructor_t create)
{
	signer_t *signer;

	signer = create(alg);
	if (signer)
	{
		char key[signer->get_key_size(signer)];
		char mac[signer->get_block_size(signer)];
		chunk_t buf;
		struct timespec start;
		u_int runs;

		memset(key, 0x12, sizeof(key));
		signer->set_key(signer, chunk_from_thing(key));

		buf = chunk_alloc(this->bench_size);
		memset(buf.ptr, 0x34, buf.len);

		runs = 0;
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			signer->get_signature(signer, buf, mac);
			runs++;
			signer->verify_signature(signer, buf, chunk_from_thing(mac));
			runs++;
		}
		free(buf.ptr);
		signer->destroy(signer);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_signer, bool,
	private_crypto_tester_t *this, integrity_algorithm_t alg,
	signer_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	signer_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	enumerator = this->signer->create_enumerator(this->signer);
	while (enumerator->enumerate(enumerator, &vector))
	{
		signer_t *signer;
		chunk_t key, data, mac;

		if (vector->alg != alg)
		{
			continue;
		}

		tested++;
		signer = create(alg);
		if (!signer)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: creating instance failed",
				 integrity_algorithm_names, alg, plugin_name);
			failed = TRUE;
			break;
		}

		failed = FALSE;

		key = chunk_create(vector->key, signer->get_key_size(signer));
		signer->set_key(signer, key);

		/* allocated signature */
		data = chunk_create(vector->data, vector->len);
		signer->allocate_signature(signer, data, &mac);
		if (mac.len != signer->get_block_size(signer))
		{
			failed = TRUE;
		}
		if (!memeq(vector->mac, mac.ptr, mac.len))
		{
			failed = TRUE;
		}
		/* signature to existing buffer */
		memset(mac.ptr, 0, mac.len);
		signer->get_signature(signer, data, mac.ptr);
		if (!memeq(vector->mac, mac.ptr, mac.len))
		{
			failed = TRUE;
		}
		/* signature verification, good case */
		if (!signer->verify_signature(signer, data, mac))
		{
			failed = TRUE;
		}
		/* signature verification, bad case */
		*(mac.ptr + mac.len - 1) += 1;
		if (signer->verify_signature(signer, data, mac))
		{
			failed = TRUE;
		}
		/* signature to existing buffer, using append mode */
		if (data.len > 2)
		{
			signer->allocate_signature(signer, chunk_create(data.ptr, 1), NULL);
			signer->get_signature(signer, chunk_create(data.ptr + 1, 1), NULL);
			if (!signer->verify_signature(signer, chunk_skip(data, 2),
										  chunk_create(vector->mac, mac.len)))
			{
				failed = TRUE;
			}
		}
		free(mac.ptr);

		signer->destroy(signer);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 integrity_algorithm_names, alg, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
			 this->required ? "disabled" : "enabled ",
			 integrity_algorithm_names, alg, plugin_name);
		return !this->required;
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_signer(this, alg, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 integrity_algorithm_names, alg, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 integrity_algorithm_names, alg, plugin_name, tested);
		}
	}
	return !failed;
}

/**
 * Benchmark a hasher
 */
static u_int bench_hasher(private_crypto_tester_t *this,
	hash_algorithm_t alg, hasher_constructor_t create)
{
	hasher_t *hasher;

	hasher = create(alg);
	if (hasher)
	{
		char hash[hasher->get_hash_size(hasher)];
		chunk_t buf;
		struct timespec start;
		u_int runs;

		buf = chunk_alloc(this->bench_size);
		memset(buf.ptr, 0x34, buf.len);

		runs = 0;
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			hasher->get_hash(hasher, buf, hash);
			runs++;
		}
		free(buf.ptr);
		hasher->destroy(hasher);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_hasher, bool,
	private_crypto_tester_t *this, hash_algorithm_t alg,
	hasher_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	hasher_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	enumerator = this->hasher->create_enumerator(this->hasher);
	while (enumerator->enumerate(enumerator, &vector))
	{
		hasher_t *hasher;
		chunk_t data, hash;

		if (vector->alg != alg)
		{
			continue;
		}

		tested++;
		hasher = create(alg);
		if (!hasher)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: creating instance failed",
				 hash_algorithm_names, alg, plugin_name);
			failed = TRUE;
			break;
		}

		failed = FALSE;

		/* allocated hash */
		data = chunk_create(vector->data, vector->len);
		hasher->allocate_hash(hasher, data, &hash);
		if (hash.len != hasher->get_hash_size(hasher))
		{
			failed = TRUE;
		}
		if (!memeq(vector->hash, hash.ptr, hash.len))
		{
			failed = TRUE;
		}
		/* hash to existing buffer */
		memset(hash.ptr, 0, hash.len);
		hasher->get_hash(hasher, data, hash.ptr);
		if (!memeq(vector->hash, hash.ptr, hash.len))
		{
			failed = TRUE;
		}
		/* hasher to existing buffer, using append mode */
		if (data.len > 2)
		{
			memset(hash.ptr, 0, hash.len);
			hasher->allocate_hash(hasher, chunk_create(data.ptr, 1), NULL);
			hasher->get_hash(hasher, chunk_create(data.ptr + 1, 1), NULL);
			hasher->get_hash(hasher, chunk_skip(data, 2), hash.ptr);
			if (!memeq(vector->hash, hash.ptr, hash.len))
			{
				failed = TRUE;
			}
		}
		free(hash.ptr);

		hasher->destroy(hasher);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 hash_algorithm_names, alg, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
			 this->required ? "disabled" : "enabled ",
			 hash_algorithm_names, alg, plugin_name);
		return !this->required;
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_hasher(this, alg, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 hash_algorithm_names, alg, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 hash_algorithm_names, alg, plugin_name, tested);
		}
	}
	return !failed;
}

/**
 * Benchmark a PRF
 */
static u_int bench_prf(private_crypto_tester_t *this,
					   pseudo_random_function_t alg, prf_constructor_t create)
{
	prf_t *prf;

	prf = create(alg);
	if (prf)
	{
		char bytes[prf->get_block_size(prf)];
		chunk_t buf;
		struct timespec start;
		u_int runs;

		buf = chunk_alloc(this->bench_size);
		memset(buf.ptr, 0x34, buf.len);

		runs = 0;
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			prf->get_bytes(prf, buf, bytes);
			runs++;
		}
		free(buf.ptr);
		prf->destroy(prf);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_prf, bool,
	private_crypto_tester_t *this, pseudo_random_function_t alg,
	prf_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	prf_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	enumerator = this->prf->create_enumerator(this->prf);
	while (enumerator->enumerate(enumerator, &vector))
	{
		prf_t *prf;
		chunk_t key, seed, out;

		if (vector->alg != alg)
		{
			continue;
		}

		tested++;
		prf = create(alg);
		if (!prf)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: creating instance failed",
				 pseudo_random_function_names, alg, plugin_name);
			failed = TRUE;
			break;
		}

		failed = FALSE;

		key = chunk_create(vector->key, vector->key_size);
		prf->set_key(prf, key);

		/* allocated bytes */
		seed = chunk_create(vector->seed, vector->len);
		prf->allocate_bytes(prf, seed, &out);
		if (out.len != prf->get_block_size(prf))
		{
			failed = TRUE;
		}
		if (!memeq(vector->out, out.ptr, out.len))
		{
			failed = TRUE;
		}
		/* bytes to existing buffer */
		memset(out.ptr, 0, out.len);
		if (vector->stateful)
		{
			prf->set_key(prf, key);
		}
		prf->get_bytes(prf, seed, out.ptr);
		if (!memeq(vector->out, out.ptr, out.len))
		{
			failed = TRUE;
		}
		/* bytes to existing buffer, using append mode */
		if (seed.len > 2)
		{
			memset(out.ptr, 0, out.len);
			if (vector->stateful)
			{
				prf->set_key(prf, key);
			}
			prf->allocate_bytes(prf, chunk_create(seed.ptr, 1), NULL);
			prf->get_bytes(prf, chunk_create(seed.ptr + 1, 1), NULL);
			prf->get_bytes(prf, chunk_skip(seed, 2), out.ptr);
			if (!memeq(vector->out, out.ptr, out.len))
			{
				failed = TRUE;
			}
		}
		free(out.ptr);

		prf->destroy(prf);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 pseudo_random_function_names, alg, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
			 this->required ? "disabled" : "enabled ",
			 pseudo_random_function_names, alg, plugin_name);
		return !this->required;
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_prf(this, alg, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 pseudo_random_function_names, alg, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 pseudo_random_function_names, alg, plugin_name, tested);
		}
	}
	return !failed;
}

/**
 * Benchmark a RNG
 */
static u_int bench_rng(private_crypto_tester_t *this,
					   rng_quality_t quality, rng_constructor_t create)
{
	rng_t *rng;

	rng = create(quality);
	if (rng)
	{
		struct timespec start;
		chunk_t buf;
		u_int runs;

		runs = 0;
		buf = chunk_alloc(this->bench_size);
		start_timing(&start);
		while (end_timing(&start) < this->bench_time)
		{
			rng->get_bytes(rng, buf.len, buf.ptr);
			runs++;
		}
		free(buf.ptr);
		rng->destroy(rng);

		return runs;
	}
	return 0;
}

METHOD(crypto_tester_t, test_rng, bool,
	private_crypto_tester_t *this, rng_quality_t quality,
	rng_constructor_t create, u_int *speed, const char *plugin_name)
{
	enumerator_t *enumerator;
	rng_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;

	if (!this->rng_true && quality == RNG_TRUE)
	{
		DBG1(DBG_LIB, "enabled  %N[%s]: skipping test (disabled by config)",
			 rng_quality_names, quality, plugin_name);
		return TRUE;
	}

	enumerator = this->rng->create_enumerator(this->rng);
	while (enumerator->enumerate(enumerator, &vector))
	{
		rng_t *rng;
		chunk_t data;

		if (vector->quality != quality)
		{
			continue;
		}

		tested++;
		rng = create(quality);
		if (!rng)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: creating instance failed",
				 rng_quality_names, quality, plugin_name);
			failed = TRUE;
			break;
		}

		failed = FALSE;

		/* allocated bytes */
		rng->allocate_bytes(rng, vector->len, &data);
		if (data.len != vector->len)
		{
			failed = TRUE;
		}
		if (!vector->test(vector->user, data))
		{
			failed = TRUE;
		}
		/* bytes to existing buffer */
		memset(data.ptr, 0, data.len);
		rng->get_bytes(rng, vector->len, data.ptr);
		if (!vector->test(vector->user, data))
		{
			failed = TRUE;
		}
		free(data.ptr);

		rng->destroy(rng);
		if (failed)
		{
			DBG1(DBG_LIB, "disabled %N[%s]: %s test vector failed",
				 rng_quality_names, quality, plugin_name, get_name(vector));
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1(DBG_LIB, "%s %N[%s]: no test vectors found",
			 this->required ? ", disabled" : "enabled ",
			 rng_quality_names, quality, plugin_name);
		return !this->required;
	}
	if (!failed)
	{
		if (speed)
		{
			*speed = bench_rng(this, quality, create);
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors, %d points",
				 rng_quality_names, quality, plugin_name, tested, *speed);
		}
		else
		{
			DBG1(DBG_LIB, "enabled  %N[%s]: passed %u test vectors",
				 rng_quality_names, quality, plugin_name, tested);
		}
	}
	return !failed;
}

METHOD(crypto_tester_t, add_crypter_vector, void,
	private_crypto_tester_t *this, crypter_test_vector_t *vector)
{
	this->crypter->insert_last(this->crypter, vector);
}

METHOD(crypto_tester_t, add_aead_vector, void,
	private_crypto_tester_t *this, aead_test_vector_t *vector)
{
	this->aead->insert_last(this->aead, vector);
}

METHOD(crypto_tester_t, add_signer_vector, void,
	private_crypto_tester_t *this, signer_test_vector_t *vector)
{
	this->signer->insert_last(this->signer, vector);
}

METHOD(crypto_tester_t, add_hasher_vector, void,
	private_crypto_tester_t *this, hasher_test_vector_t *vector)
{
	this->hasher->insert_last(this->hasher, vector);
}

METHOD(crypto_tester_t, add_prf_vector, void,
	private_crypto_tester_t *this, prf_test_vector_t *vector)
{
	this->prf->insert_last(this->prf, vector);
}

METHOD(crypto_tester_t, add_rng_vector, void,
	private_crypto_tester_t *this, rng_test_vector_t *vector)
{
	this->rng->insert_last(this->rng, vector);
}

METHOD(crypto_tester_t, destroy, void,
	private_crypto_tester_t *this)
{
	this->crypter->destroy(this->crypter);
	this->aead->destroy(this->aead);
	this->signer->destroy(this->signer);
	this->hasher->destroy(this->hasher);
	this->prf->destroy(this->prf);
	this->rng->destroy(this->rng);
	free(this);
}

/**
 * See header
 */
crypto_tester_t *crypto_tester_create()
{
	private_crypto_tester_t *this;

	INIT(this,
		.public = {
			.test_crypter = _test_crypter,
			.test_aead = _test_aead,
			.test_signer = _test_signer,
			.test_hasher = _test_hasher,
			.test_prf = _test_prf,
			.test_rng = _test_rng,
			.add_crypter_vector = _add_crypter_vector,
			.add_aead_vector = _add_aead_vector,
			.add_signer_vector = _add_signer_vector,
			.add_hasher_vector = _add_hasher_vector,
			.add_prf_vector = _add_prf_vector,
			.add_rng_vector = _add_rng_vector,
			.destroy = _destroy,
		},
		.crypter = linked_list_create(),
		.aead = linked_list_create(),
		.signer = linked_list_create(),
		.hasher = linked_list_create(),
		.prf = linked_list_create(),
		.rng = linked_list_create(),

		.required = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.required", FALSE),
		.rng_true = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.rng_true", FALSE),
		.bench_time = lib->settings->get_int(lib->settings,
								"libstrongswan.crypto_test.bench_time", 50),
		.bench_size = lib->settings->get_int(lib->settings,
								"libstrongswan.crypto_test.bench_size", 1024),
	);

	/* enforce a block size of 16, should be fine for all algorithms */
	this->bench_size = this->bench_size / 16 * 16;

	return &this->public;
}

