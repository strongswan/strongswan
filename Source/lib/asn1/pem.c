/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include "pem.h"
#include "ttodata.h"

#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>


/*
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

/*
 * compare string with chunk
 */
static bool match(const char *pattern, const chunk_t *ch)
{
	return ch->len == strlen(pattern) && strncmp(pattern, ch->ptr, ch->len) == 0;
}

/*
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
			return TRUE;
		}
		line->ptr++;  line->len--;  name.len++;
	}
	return FALSE;
}

/*
 * eat whitespace
 */
static void eat_whitespace(chunk_t *src)
{
	while (src->len > 0 && (*src->ptr == ' ' || *src->ptr == '\t'))
	{
		src->ptr++;  src->len--;
	}
}

/*
 * extracts a token ending with a given termination symbol
 */
static bool extract_token(chunk_t *token, char termination, chunk_t *src)
{
	u_char *eot = memchr(src->ptr, termination, src->len);
	
	/* initialize empty token */
	*token = CHUNK_INITIALIZER;
	
	if (eot == NULL) /* termination symbol not found */
	{
		return FALSE;
	}
	
	/* extract token */
	token->ptr = src->ptr;
	token->len = (u_int)(eot - src->ptr);
	
	/* advance src pointer after termination symbol */
	src->ptr = eot + 1;
	src->len -= (token->len + 1);
	
	return TRUE;
}

/*
 * extracts a name: value pair from the PEM header
 */
static bool extract_parameter(chunk_t *name, chunk_t *value, chunk_t *line)
{
	/* extract name */
	if (!extract_token(name,':', line))
	{
		return FALSE;
	}
	
	eat_whitespace(line);
	
	/* extract value */
	*value = *line;
	return TRUE;
}

/*
 *  fetches a new line terminated by \n or \r\n
 */
static bool fetchline(chunk_t *src, chunk_t *line)
{
	if (src->len == 0) /* end of src reached */
		return FALSE;

	if (extract_token(line, '\n', src))
	{
		if (line->len > 0 && *(line->ptr + line->len -1) == '\r')
			line->len--;  /* remove optional \r */
	}
	else /*last line ends without newline */
	{
		*line = *src;
		src->ptr += src->len;
		src->len = 0;
	}
	return TRUE;
}

/*
 * decrypts a DES-EDE-CBC encrypted data block
 */
static status_t pem_decrypt(chunk_t *blob, chunk_t *iv, char *passphrase)
{
	hasher_t *hasher;
	crypter_t *crypter;
	chunk_t hash;
	chunk_t decrypted;
	chunk_t pass = {passphrase, strlen(passphrase)};
	chunk_t key = {alloca(24), 24};
	u_int8_t padding, *last_padding_pos, *first_padding_pos;
	
	/* build key from passphrase and IV */
	hasher = hasher_create(HASH_MD5);
	hash.len = hasher->get_block_size(hasher);
	hash.ptr = alloca(hash.len);
	hasher->get_hash(hasher, pass, NULL);
	hasher->get_hash(hasher, *iv, hash.ptr);
	
	memcpy(key.ptr, hash.ptr, hash.len);
	
	hasher->get_hash(hasher, hash, NULL);
	hasher->get_hash(hasher, pass, NULL);
	hasher->get_hash(hasher, *iv, hash.ptr);
	
	memcpy(key.ptr + hash.len, hash.ptr, key.len - hash.len);
	
	hasher->destroy(hasher);
	
	/* decrypt blob */
	crypter = crypter_create(ENCR_3DES, 0);
	crypter->set_key(crypter, key);
	crypter->decrypt(crypter, *blob, *iv, &decrypted);
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
			return FALSE;
	}
	/* remove padding */
	blob->len -= padding;
	return TRUE;
}

/*  Converts a PEM encoded file into its binary form
 *
 *  RFC 1421 Privacy Enhancement for Electronic Mail, February 1993
 *  RFC 934 Message Encapsulation, January 1985
 */
status_t pemtobin(chunk_t *blob, char *pass)
{
	typedef enum {
		PEM_PRE    = 0,
		PEM_MSG    = 1,
		PEM_HEADER = 2,
		PEM_BODY   = 3,
		PEM_POST   = 4,
		PEM_ABORT  = 5
	} state_t;

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
				chunk_t name  = CHUNK_INITIALIZER;
				chunk_t value = CHUNK_INITIALIZER;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0)
				{
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a name: value pair */
				if (!extract_parameter(&name, &value, &line))
					continue;

				if (match("Proc-Type", &name) && *value.ptr == '4')
					encrypted = TRUE;
				else if (match("DEK-Info", &name))
				{
					const char *ugh = NULL;
					size_t len = 0;
					chunk_t dek;

					if (!extract_token(&dek, ',', &value))
						dek = value;

					/* we support DES-EDE3-CBC encrypted files, only */
					if (!match("DES-EDE3-CBC", &dek))
						return NOT_SUPPORTED;

					eat_whitespace(&value);
					ugh = ttodata(value.ptr, value.len, 16, iv.ptr, 16, &len);
					if (ugh)
						return PARSE_ERROR;

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
		return PARSE_ERROR;

	if (encrypted)
		return pem_decrypt(blob, &iv, pass);
	else
		return SUCCESS;
}
