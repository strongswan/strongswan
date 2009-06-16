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
};

/**
 * Implementation of crypto_tester_t.test_crypter
 */
static bool test_crypter(private_crypto_tester_t *this,
	encryption_algorithm_t alg, size_t key_size, crypter_constructor_t create)
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
		{	/* key size not supported... */
			continue;
		}
		
		failed = FALSE;
		tested++;
		
		key = chunk_create(vector->key, crypter->get_key_size(crypter));
		crypter->set_key(crypter, key);
		iv = chunk_create(vector->iv, crypter->get_block_size(crypter));
		
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
			DBG1("test vector %d failed, %N disabled",
				 tested, encryption_algorithm_names, alg);
			break;
		}
		DBG2("%N test vector %d successful",
			 encryption_algorithm_names, alg, tested);
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1("no test vectors found for %N%s",
			 encryption_algorithm_names, alg, 
			 this->required ? ", disabled" : "");
		return !this->required;
	}
	if (!failed)
	{
		DBG1("successfully tested %d test vectors for %N",
			 tested, encryption_algorithm_names, alg);
	}
	return !failed;
}

/**
 * Implementation of crypto_tester_t.test_signer
 */
static bool test_signer(private_crypto_tester_t *this,
						integrity_algorithm_t alg, signer_constructor_t create)
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
			DBG1("creating instance failed, %N disabled",
				 integrity_algorithm_names, alg);
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
			memset(mac.ptr, 0, mac.len);
			signer->allocate_signature(signer, chunk_create(data.ptr, 1), NULL);
			signer->get_signature(signer, chunk_create(data.ptr + 1, 1), NULL);
			signer->get_signature(signer, chunk_skip(data, 2), mac.ptr);
			if (!memeq(vector->mac, mac.ptr, mac.len))
			{
				failed = TRUE;
			}
		}
		free(mac.ptr);
		
		signer->destroy(signer);
		if (failed)
		{
			DBG1("test vector %d failed, %N disabled",
				 tested, integrity_algorithm_names, alg);
			break;
		}
		DBG2(" %N test vector %d successful",
			 integrity_algorithm_names, alg, tested);
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1("no test vectors found for %N%s",
			 integrity_algorithm_names, alg, 
			 this->required ? ", disabled" : "");
		return !this->required;
	}
	if (!failed)
	{
		DBG1("successfully tested %d test vectors for %N",
			 tested, integrity_algorithm_names, alg);
	}
	return !failed;
}

/**
 * Implementation of hasher_t.test_hasher
 */
static bool test_hasher(private_crypto_tester_t *this, hash_algorithm_t alg,
						hasher_constructor_t create)
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
			DBG1("creating instance failed, %N disabled",
				 hash_algorithm_names, alg);
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
			DBG1("test vector %d failed, %N disabled",
				 tested, hash_algorithm_names, alg);
			break;
		}
		DBG2("%N test vector %d successful",
			 hash_algorithm_names, alg, tested);
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1("no test vectors found for %N%s",
			 hash_algorithm_names, alg, 
			 this->required ? ", disabled" : "");
		return !this->required;
	}
	if (!failed)
	{
		DBG1("successfully tested %d test vectors for %N",
			 tested, hash_algorithm_names, alg);
	}
	return !failed;
}

/**
 * Implementation of crypto_tester_t.test_prf
 */
static bool test_prf(private_crypto_tester_t *this,
					 pseudo_random_function_t alg, prf_constructor_t create)
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
			DBG1("creating instance failed, %N disabled",
				 pseudo_random_function_names, alg);
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
			DBG1("test vector %d failed, %N disabled",
				 tested, pseudo_random_function_names, alg);
			break;
		}
		DBG2("%N test vector %d successful",
			 pseudo_random_function_names, alg, tested);
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1("no test vectors found for %N%s",
			 pseudo_random_function_names, alg, 
			 this->required ? ", disabled" : "");
		return !this->required;
	}
	if (!failed)
	{
		DBG1("successfully tested %d testvectors for %N",
			 tested, pseudo_random_function_names, alg);
	}
	return !failed;
}

/**
 * Implementation of crypto_tester_t.test_rng
 */
static bool test_rng(private_crypto_tester_t *this, rng_quality_t quality,
					 rng_constructor_t create)
{
	enumerator_t *enumerator;
	rng_test_vector_t *vector;
	bool failed = FALSE;
	u_int tested = 0;
	
	if (!this->rng_true && quality == RNG_TRUE)
	{
		DBG1("skipping %N test, disabled by config", rng_quality_names, quality);
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
			DBG1("creating instance failed, %N disabled",
				 rng_quality_names, quality);
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
			DBG1("test vector %d failed, %N disabled",
				 tested, rng_quality_names, quality);
			break;
		}
		DBG2("%N test vector %d successful", rng_quality_names, quality, tested);
	}
	enumerator->destroy(enumerator);
	if (!tested)
	{
		DBG1("no test vectors found for %N%s",
			 rng_quality_names, quality, this->required ? ", disabled" : "");
		return !this->required;
	}
	if (!failed)
	{
		DBG1("successfully tested %d testvectors for %N",
			 tested, rng_quality_names, quality);
	}
	return !failed;
}

/**
 * Implementation of crypter_tester_t.add_crypter_vector
 */
static void add_crypter_vector(private_crypto_tester_t *this,
							   crypter_test_vector_t *vector)
{
	this->crypter->insert_last(this->crypter, vector);
}

/**
 * Implementation of crypter_tester_t.add_signer_vector
 */
static void add_signer_vector(private_crypto_tester_t *this,
							  signer_test_vector_t *vector)
{
	this->signer->insert_last(this->signer, vector);
}

/**
 * Implementation of crypter_tester_t.add_hasher_vector
 */
static void add_hasher_vector(private_crypto_tester_t *this,
							  hasher_test_vector_t *vector)
{
	this->hasher->insert_last(this->hasher, vector);
}

/**
 * Implementation of crypter_tester_t.add_prf_vector
 */
static void add_prf_vector(private_crypto_tester_t *this,
						   prf_test_vector_t *vector)
{
	this->prf->insert_last(this->prf, vector);
}

/**
 * Implementation of crypter_tester_t.add_rng_vector
 */
static void add_rng_vector(private_crypto_tester_t *this,
						   rng_test_vector_t *vector)
{
	this->rng->insert_last(this->rng, vector);
}

/**
 * Implementation of crypto_tester_t.destroy.
 */
static void destroy(private_crypto_tester_t *this)
{
	this->crypter->destroy(this->crypter);
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
	private_crypto_tester_t *this = malloc_thing(private_crypto_tester_t);
	
	this->public.test_crypter = (bool(*)(crypto_tester_t*, encryption_algorithm_t alg,size_t key_size, crypter_constructor_t create))test_crypter;
	this->public.test_signer = (bool(*)(crypto_tester_t*, integrity_algorithm_t alg, signer_constructor_t create))test_signer;
	this->public.test_hasher = (bool(*)(crypto_tester_t*, hash_algorithm_t alg, hasher_constructor_t create))test_hasher;
	this->public.test_prf = (bool(*)(crypto_tester_t*, pseudo_random_function_t alg, prf_constructor_t create))test_prf;
	this->public.test_rng = (bool(*)(crypto_tester_t*, rng_quality_t quality, rng_constructor_t create))test_rng;
	this->public.add_crypter_vector = (void(*)(crypto_tester_t*, crypter_test_vector_t *vector))add_crypter_vector;
	this->public.add_signer_vector = (void(*)(crypto_tester_t*, signer_test_vector_t *vector))add_signer_vector;
	this->public.add_hasher_vector = (void(*)(crypto_tester_t*, hasher_test_vector_t *vector))add_hasher_vector;
	this->public.add_prf_vector = (void(*)(crypto_tester_t*, prf_test_vector_t *vector))add_prf_vector;
	this->public.add_rng_vector = (void(*)(crypto_tester_t*, rng_test_vector_t *vector))add_rng_vector;
	this->public.destroy = (void(*)(crypto_tester_t*))destroy;
	
	this->crypter = linked_list_create();
	this->signer = linked_list_create();
	this->hasher = linked_list_create();
	this->prf = linked_list_create();
	this->rng = linked_list_create();
	
	this->required = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.required", FALSE);
	this->rng_true = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.rng_true", FALSE);
	
	return &this->public;
}

