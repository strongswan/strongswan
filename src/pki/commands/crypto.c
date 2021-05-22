/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 *
 * Copyright (C) 2015-2016 Andreas Steffen
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

#include "pki.h"

#include <crypto/mac.h>
#include <crypto/prfs/prf.h>

#include <errno.h>

#define GMSDF_RNG	2
#define GMSDF_HASH	3
#define GMSDF_CRYPTER	4
#define GMSDF_PRF	5
#define GMSDF_SIGNER	6
#define GMSDF_DH	7
#define GMSDF_SM2	8

void print_hex(unsigned char *name, unsigned char *c, int n)
{
	int i;

	fprintf(stderr, "\n------------start[%s ,len = %d, start ]", name, n);
	for(i=0;i<n;i++)
	{
		if(i%16==0){
			fprintf(stderr, "\n%04d:  ", i);
		}
		fprintf(stderr, "%02X",c[i]);
		if(i%4==3)
			fprintf(stderr, " ");

	}
	fprintf(stderr, "\n--------------end[%s ,len = %d, start ]\n\n", name, n);
}

/**
 * Read input data as chunk
 *
 */
chunk_t read_from_file(char *file)
{
	char buf[8096];
	size_t len, total = 0;
	FILE *stream;

	stream = fopen(file, "r");
	if (!stream)
	{
		return chunk_empty;
	}

	while (TRUE)
	{
		len = fread(buf + total, 1, sizeof(buf) - total, stream);
		if (len < (sizeof(buf) - total))
		{
			if (ferror(stream))
			{
				fclose(stream);
				return chunk_empty;
			}
			if (feof(stream))
			{
				fclose(stream);
				return chunk_clone(chunk_create(buf, total + len));
			}
		}
		total += len;
		if (total == sizeof(buf))
		{
			fprintf(stderr, "buffer too small to read input!\n");
			fclose(stream);
			return chunk_empty;
		}
	}
}

/**
 * Write output data from chunk to stream
 *
 */
bool write_to_file(char *file, chunk_t data)
{
	size_t len, total = 0;
	FILE *stream;

	stream = fopen(file, "r");
	if (!stream)
	{
		return FALSE;
	}

	set_file_mode(stream, CERT_ASN1_DER);
	while (total < data.len)
	{
		len = fwrite(data.ptr + total, 1, data.len - total, stream);
		if (len <= 0)
		{
			return FALSE;
		}
		total += len;
	}
	return TRUE;
}

int gmsdf_crypter_test(chunk_t data)
{
	int ret = 0;
	int key_size = 16;
	crypter_t *crypter;
	encryption_algorithm_t alg = ENCR_SM4_CBC;
	chunk_t response = chunk_empty;
	chunk_t key = chunk_empty;
	chunk_t iv = chunk_empty;
	chunk_t d = chunk_create(data.ptr, data.len&0xfff0);

	crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size);
	if (!crypter)
	{
		fprintf(stderr, "create crypter failed \n");
		return FALSE;
	}

	if(crypter->get_block_size(crypter) != key_size)
	{
		crypter->destroy(crypter);
		fprintf(stderr, "get block size failed \n");
		return FALSE;
	}

	key = chunk_alloc(key_size);
	iv = chunk_alloc(key_size);
	response = chunk_alloc(d.len);

	memset(key.ptr, 0, key.len);
	memset(iv.ptr, 0x88, iv.len);
	memset(response.ptr, 0, response.len);

	if(!crypter->set_key(crypter, key))
	{
		fprintf(stderr, "failed to set key \n");
		ret = FALSE;
	}

	print_hex("in data", d.ptr, d.len);

	if (!crypter->encrypt(crypter, d, iv, &response))
	{
		fprintf(stderr, "decryption failed \n");
		ret = FALSE;
	}

	print_hex("temp data", response.ptr, response.len);

	if (!crypter->decrypt(crypter, response, iv, &d))
	{
		fprintf(stderr, "encryption failed \n");
		ret = FALSE;
	}

	print_hex("out data", d.ptr, d.len);

	crypter->destroy(crypter);
	chunk_free(&response);
	chunk_free(&key);
	chunk_free(&iv);
	return ret;
}

int gmsdf_hash_test(chunk_t data)
{
	int ret = 0;
	hasher_t *hasher;
	hash_algorithm_t algo = HASH_SM3;
	chunk_t response = chunk_empty;

	hasher = lib->crypto->create_hasher(lib->crypto, algo);
	if (hasher == NULL)
	{
		printf(" create hasher err \n");
		ret = FAILED;
	}

	if (!hasher->allocate_hash(hasher, data, &response))
	{
		printf(" allocate hasher err \n");
		ret = FAILED;
	}

	print_hex("in  data", data.ptr, data.len);
	print_hex("out data", response.ptr, response.len);

	hasher->destroy(hasher);
	chunk_free(&response);

	return ret;
}

int gmsdf_signer_test(chunk_t data)
{
	int ret = 0;
	chunk_t key = chunk_empty;
	chunk_t sig = chunk_empty;
	integrity_algorithm_t  alg = AUTH_HMAC_SM3;
	signer_t *signer;

	signer = lib->crypto->create_signer(lib->crypto, alg);
	if(!signer)
	{
		fprintf(stderr, " mac signer create err \n");
		return FALSE;
	}

	key = chunk_alloc(signer->get_key_size(signer));
	memset(key.ptr, 0, key.len);
	sig = chunk_alloc(signer->get_block_size(signer));

	if(!signer->set_key(signer, key))
	{
		fprintf(stderr, " signer set key  failed!\n");
	}

	if(!signer->allocate_signature(signer, data, &sig))
	{
		fprintf(stderr, "creating signature failed!\n");
	}

	if (!signer->verify_signature(signer, data, sig))
	{
		fprintf(stderr, "verifying signature failed!\n");
	}

	print_hex("in  data", data.ptr, data.len);

	signer->destroy(signer);
	chunk_free(&key);
	chunk_free(&sig);
	return ret;
}

int gmsdf_dh_test(chunk_t data)
{
	int ret = 0;
	diffie_hellman_t *dh_i, *dh_r;
	diffie_hellman_group_t group = CURVE_SM2;

	chunk_t pub_i = chunk_empty;
	chunk_t pub_r = chunk_empty;
	chunk_t rsecret_i = chunk_empty;
	chunk_t rsecret_r = chunk_empty;

	dh_i = lib->crypto->create_dh(lib->crypto, group);
	if(!dh_i)
	{
		fprintf(stderr, " create dh 1 err \n");
		ret = FALSE;
	}

	dh_r = lib->crypto->create_dh(lib->crypto, group);
	if(!dh_r)
	{
		fprintf(stderr, " create dh 2 err \n");
		ret = FALSE;
	}

	ret = dh_i->get_my_public_value(dh_i, &pub_i);
	ret = dh_r->get_my_public_value(dh_r, &pub_r);

	ret = dh_i->set_other_public_value(dh_i, pub_r);
	ret = dh_r->set_other_public_value(dh_r, pub_i);

	ret = dh_i->get_shared_secret(dh_i, &rsecret_i);
	ret = dh_r->get_shared_secret(dh_r, &rsecret_r);

	print_hex("out data 1", rsecret_i.ptr, rsecret_i.len);
	print_hex("out data 2", rsecret_r.ptr, rsecret_r.len);

	dh_i->destroy(dh_i);
	dh_r->destroy(dh_r);
	chunk_free(&rsecret_i);
	chunk_free(&rsecret_r);
	chunk_free(&pub_i);
	chunk_free(&pub_r);
	return ret;
}

int gmsdf_prf_test(chunk_t data)
{
	int ret = 0;
	chunk_t key = chunk_empty;
	chunk_t response = chunk_empty;
	prf_t *prf = NULL;
	pseudo_random_function_t algo = PRF_HMAC_SM3;

	key = chunk_alloc(32);
	memset(key.ptr, 0, key.len);

	prf = lib->crypto->create_prf(lib->crypto, algo);
	if (!prf)
	{
		printf("not supported! \r");
		ret = FALSE;
	}

	if (prf->get_block_size(prf) < prf->get_key_size(prf))
	{
		printf("expansion of %N %N output not supported!\r");
		ret = FALSE;
	}

	if (!prf->set_key(prf, key) || !prf->allocate_bytes(prf, data, &response))
	{
		printf("err \r");
		ret = FALSE;
	}

	print_hex("in  data", data.ptr, data.len);
	print_hex("out data", response.ptr, response.len);

	prf->destroy(prf);
	chunk_free(&key);

	return ret;
}

int gmsdf_rng_test(chunk_t data)
{
	int ret = 0;
	rng_t *rng;
	chunk_t response = chunk_empty;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng || !rng->allocate_bytes(rng, 64, &response))
	{
		fprintf(stderr, "creating OCSP request nonce failed, no RNG found");
	}

	print_hex("out data", response.ptr, response.len);

	rng->destroy(rng);
	chunk_free(&response);

	return ret;
}

int gmsdf_sm2_test(chunk_t data)
{
	int ret = 0;
	return ret;
}

/**
 * Print a credential in a human readable form
 */
static int crypto()
{
	char *arg, *file = NULL;
	chunk_t chunk = chunk_empty;
	int type = GMSDF_HASH;
	int ret = 0;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 't':
				if (streq(arg, "crypter"))
				{
					type = GMSDF_CRYPTER;
				}
				else if (streq(arg, "hash"))
				{
					type = GMSDF_HASH;
				}
				else if (streq(arg, "prf"))
				{
					type = GMSDF_PRF;
				}
				else if (streq(arg, "signer"))
				{
					type = GMSDF_SIGNER;
				}
				else if (streq(arg, "dh"))
				{
					type = GMSDF_DH;
				}
				else if (streq(arg, "rng"))
				{
					type = GMSDF_RNG;
				}
				else if (streq(arg, "sm2"))
				{
					type = GMSDF_SM2;
				}
				else
				{
					return command_usage( "invalid input type");
				}
				continue;
			case 'i':
				file = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --print option");
		}
		break;
	}

	if (file)
	{
		chunk = read_from_file(file);
	}
	else
	{
		chunk = chunk_alloc(128);
		memset(chunk.ptr, 0, chunk.len);
	}

	switch (type)
	{
		case GMSDF_HASH:
			ret = gmsdf_hash_test(chunk);
			break;
		case GMSDF_CRYPTER:
			ret = gmsdf_crypter_test(chunk);
			break;
		case GMSDF_PRF:
			ret = gmsdf_prf_test(chunk);
			break;
		case GMSDF_SIGNER:
			ret = gmsdf_signer_test(chunk);
			break;
		case GMSDF_DH:
			ret = gmsdf_dh_test(chunk);
			break;
		case GMSDF_RNG:
			ret = gmsdf_rng_test(chunk);
			break;
		case GMSDF_SM2:
			ret = gmsdf_sm2_test(chunk);
			break;
		default: command_usage("invalid --type option");
	}

	chunk_free(&chunk);
	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t)
			{ crypto, 'm', "crypto",
			"crypto gm interface test",
			{"[--in file] "
			"[--type hash|crypter|prf|signer|dh|rng|sm2]"},
			{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"type",	't', 1, "type of credential, default: hash"},
			}
			});
}
