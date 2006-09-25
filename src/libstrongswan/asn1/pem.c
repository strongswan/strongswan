/*
 * Copyright (C) 2001-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include "asn1.h"
#include "pem.h"
#include "ttodata.h"

#include <utils/lexparser.h>
#include <utils/logger_manager.h>
#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>

#define PKCS5_SALT_LEN	8	/* bytes */

static logger_t *logger = NULL;

/**
 * initializes the PEM logger
 */
static void pem_init_logger(void)
{
	if (logger == NULL)
		logger = logger_manager->get_logger(logger_manager, ASN1);
}

/**
 * check the presence of a pattern in a character string
 */
static bool present(const char* pattern, chunk_t* ch)
{
	u_int pattern_len = strlen(pattern);

	if (ch->len >= pattern_len && strncmp(ch->ptr, pattern, pattern_len) == 0)
	{
		ch->ptr += pattern_len;
		ch->len -= pattern_len;
		return TRUE;
	}
	return FALSE;
}

/**
 * find a boundary of the form -----tag name-----
 */
static bool find_boundary(const char* tag, chunk_t *line)
{
	chunk_t name = CHUNK_INITIALIZER;

	if (!present("-----", line))
		return FALSE;
	if (!present(tag, line))
		return FALSE;
	if (*line->ptr != ' ')
		return FALSE;
	line->ptr++;  line->len--;
	
	/* extract name */
	name.ptr = line->ptr;
	while (line->len > 0)
	{
		if (present("-----", line))
		{
			logger->log(logger, CONTROL|LEVEL2,
		 		"  -----%s %.*s-----", tag, (int)name.len, name.ptr);
			return TRUE;
		}
		line->ptr++;  line->len--;  name.len++;
	}
	return FALSE;
}

/*
 * decrypts a DES-EDE-CBC encrypted data block
 */
static err_t pem_decrypt(chunk_t *blob, encryption_algorithm_t alg, size_t key_size,
						 chunk_t *iv, chunk_t *passphrase)
{
	hasher_t *hasher;
	crypter_t *crypter;
	chunk_t salt = { iv->ptr, PKCS5_SALT_LEN };
	chunk_t hash;
	chunk_t decrypted;
	chunk_t key = {alloca(key_size), key_size};
	u_int8_t padding, *last_padding_pos, *first_padding_pos;
	
	if (passphrase == NULL || passphrase->len == 0)
		return "missing passphrase";

	/* build key from passphrase and IV */
	hasher = hasher_create(HASH_MD5);
	hash.len = hasher->get_hash_size(hasher);
	hash.ptr = alloca(hash.len);
	hasher->get_hash(hasher, *passphrase, NULL);
	hasher->get_hash(hasher, salt, hash.ptr);
	memcpy(key.ptr, hash.ptr, hash.len);

	if (key.len > hash.len)
	{
		hasher->get_hash(hasher, hash, NULL);
		hasher->get_hash(hasher, *passphrase, NULL);
		hasher->get_hash(hasher, salt, hash.ptr);	
		memcpy(key.ptr + hash.len, hash.ptr, key.len - hash.len);
	}	
	hasher->destroy(hasher);
	
	/* decrypt blob */
	crypter = crypter_create(alg, key_size);
	crypter->set_key(crypter, key);
	if (crypter->decrypt(crypter, *blob, *iv, &decrypted) != SUCCESS)
	{
		return "data size is not multiple of block size";
	}
	memcpy(blob->ptr, decrypted.ptr, blob->len);
	chunk_free(&decrypted);
	
	/* determine amount of padding */
	last_padding_pos = blob->ptr + blob->len - 1;
	padding = *last_padding_pos;
	first_padding_pos = (padding > blob->len) ? blob->ptr : last_padding_pos - padding;

	/* check the padding pattern */
	while (--last_padding_pos > first_padding_pos)
	{
		if (*last_padding_pos != padding)
			return "invalid passphrase";
	}
	/* remove padding */
	blob->len -= padding;
	return NULL;
}

/*  Converts a PEM encoded file into its binary form
 *
 *  RFC 1421 Privacy Enhancement for Electronic Mail, February 1993
 *  RFC 934 Message Encapsulation, January 1985
 */
err_t pem_to_bin(chunk_t *blob, chunk_t *passphrase, bool *pgp)
{
	typedef enum {
		PEM_PRE    = 0,
		PEM_MSG    = 1,
		PEM_HEADER = 2,
		PEM_BODY   = 3,
		PEM_POST   = 4,
		PEM_ABORT  = 5
	} state_t;

	encryption_algorithm_t alg = ENCR_UNDEFINED;
	size_t key_size = 0;

	bool encrypted = FALSE;

	state_t state  = PEM_PRE;

	chunk_t src    = *blob;
	chunk_t dst    = *blob;
	chunk_t line   = CHUNK_INITIALIZER;
	chunk_t iv     = CHUNK_INITIALIZER;

	u_char iv_buf[16]; /* MD5 digest size */

	/* zero size of converted blob */
	dst.len = 0;

	/* zero size of IV */
	iv.ptr = iv_buf;
	iv.len = 0;

	pem_init_logger();

	while (fetchline(&src, &line))
	{
		if (state == PEM_PRE)
		{
			if (find_boundary("BEGIN", &line))
			{
				state = PEM_MSG;
			}
			continue;
		}
		else
		{
			if (find_boundary("END", &line))
			{
				state = PEM_POST;
				break;
			}
			if (state == PEM_MSG)
			{
				state = (memchr(line.ptr, ':', line.len) == NULL) ? PEM_BODY : PEM_HEADER;
			}
			if (state == PEM_HEADER)
			{
				err_t ugh = NULL;
				chunk_t name  = CHUNK_INITIALIZER;
				chunk_t value = CHUNK_INITIALIZER;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0)
				{
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a parameter: value pair */
				logger->log(logger, CONTROL|LEVEL2, "  %.*s", (int)line.len, line.ptr);
				ugh = extract_parameter_value(&name, &value, &line);
				if (ugh != NULL)
					continue;

				if (match("Proc-Type", &name) && *value.ptr == '4')
					encrypted = TRUE;
				else if (match("DEK-Info", &name))
				{
					size_t len = 0;
					chunk_t dek;

					if (!extract_token(&dek, ',', &value))
						dek = value;

					/* we support DES-EDE3-CBC encrypted files, only */
					if (match("DES-EDE3-CBC", &dek))
					{
						alg = ENCR_3DES;
						key_size = 24;
					}
					else if (match("AES-128-CBC", &dek))
					{
						alg = ENCR_AES_CBC;
						key_size = 16;
					}
					else if (match("AES-192-CBC", &dek))
					{
						alg = ENCR_AES_CBC;
						key_size = 24;
					}
					else if (match("AES-256-CBC", &dek))
					{
						alg = ENCR_AES_CBC;
						key_size = 32;
					}
					else
					{
						return "encryption algorithm not supported";
					}

					eat_whitespace(&value);
					ugh = ttodata(value.ptr, value.len, 16, iv.ptr, 16, &len);
					if (ugh)
						return "error in IV";

					iv.len = len;
				}
			}
			else /* state is PEM_BODY */
			{
				const char *ugh = NULL;
				size_t len = 0;
				chunk_t data;
				
				/* remove any trailing whitespace */
				if (!extract_token(&data ,' ', &line))
				{
					data = line;
				}
				
				/* check for PGP armor checksum */
				if (*data.ptr == '=')
				{
					*pgp = TRUE;
					data.ptr++;
					data.len--;
					logger->log(logger, CONTROL|LEVEL2, "  Armor checksum: %.*s",
								(int)data.len, data.ptr);
		    		continue;
				}

				ugh = ttodata(data.ptr, data.len, 64, dst.ptr, blob->len - dst.len, &len);
				if (ugh)
				{
					state = PEM_ABORT;
					break;
				}
				else
				{
					dst.ptr += len;
					dst.len += len;
				}
			}
		}
	}
	/* set length to size of binary blob */
	blob->len = dst.len;

	if (state != PEM_POST)
		return "file coded in unknown format, discarded";

	return (encrypted)? pem_decrypt(blob, alg, key_size, &iv, passphrase) : NULL;
}

/* load a coded key or certificate file with autodetection
 * of binary DER or base64 PEM ASN.1 formats and armored PGP format
 */
bool pem_asn1_load_file(const char *filename, chunk_t *passphrase,
						const char *type, chunk_t *blob, bool *pgp)
{
	err_t ugh = NULL;

	FILE *fd = fopen(filename, "r");

	pem_init_logger();

	if (fd)
	{
		int bytes;
		fseek(fd, 0, SEEK_END );
		blob->len = ftell(fd);
		rewind(fd);
		blob->ptr = malloc(blob->len);
		bytes = fread(blob->ptr, 1, blob->len, fd);
		fclose(fd);
		logger->log(logger, CONTROL, "  loading %s file '%s' (%d bytes)", type, filename, bytes);

		*pgp = FALSE;

		/* try DER format */
		if (is_asn1(*blob))
		{
			logger->log(logger, CONTROL|LEVEL1, "  file coded in DER format");
			return TRUE;
		}

		if (passphrase != NULL)
			logger->log_bytes(logger, PRIVATE, "  passphrase:", passphrase->ptr, passphrase->len);

		/* try PEM format */
		ugh = pem_to_bin(blob, passphrase, pgp);

		if (ugh == NULL)
		{
			if (*pgp)
			{
				logger->log(logger, CONTROL|LEVEL1, "  file coded in armored PGP format");
				return TRUE;
			}
			if (is_asn1(*blob))
			{
				logger->log(logger, CONTROL|LEVEL1, "  file coded in PEM format");
				return TRUE;
			}
			ugh = "file coded in unknown format, discarded";
		}

		/* a conversion error has occured */
		logger->log(logger, ERROR, "  %s", ugh);
		chunk_free(blob);
	}
	else
	{
		logger->log(logger, ERROR, "  could not open %s file '%s'", type, filename);
	}
	return FALSE;
}
