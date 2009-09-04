/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2001-2008 Andreas Steffen
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

#include "pem_builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <debug.h>
#include <library.h>
#include <utils/lexparser.h>
#include <asn1/asn1.h>
#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>

#define PKCS5_SALT_LEN	8	/* bytes */

typedef struct private_builder_t private_builder_t;

/**
 * Builder implementation for PEM decoding
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** credential type we are building */
	credential_type_t type;
	/** subtype (keytype, certtype) of the credential we build */
	int subtype;
	/** path to file, if we are reading from a file */
	char *file;
	/** file description, if we are reading from a fd */
	int fd;
	/** PEM encoding of the credential */
	chunk_t pem;
	/** PEM decryption passphrase, if given */
	chunk_t passphrase;
	/** supplied callback to read passphrase */
	chunk_t (*cb)(void *data, int try);
	/** user data to callback */
	void *data;
	/** X509 flags to pass along */
	int flags;
};

/**
 * check the presence of a pattern in a character string, skip if found
 */
static bool present(char* pattern, chunk_t* ch)
{
	u_int len = strlen(pattern);

	if (ch->len >= len && strneq(ch->ptr, pattern, len))
	{
		*ch = chunk_skip(*ch, len);
		return TRUE;
	}
	return FALSE;
}

/**
 * find a boundary of the form -----tag name-----
 */
static bool find_boundary(char* tag, chunk_t *line)
{
	chunk_t name = chunk_empty;

	if (!present("-----", line) ||
		!present(tag, line) ||
		*line->ptr != ' ')
	{
		return FALSE;
	}
	*line = chunk_skip(*line, 1);

	/* extract name */
	name.ptr = line->ptr;
	while (line->len > 0)
	{
		if (present("-----", line))
		{
			DBG2("  -----%s %.*s-----", tag, (int)name.len, name.ptr);
			return TRUE;
		}
		line->ptr++;  line->len--;  name.len++;
	}
	return FALSE;
}

/*
 * decrypts a passphrase protected encrypted data block
 */
static status_t pem_decrypt(chunk_t *blob, encryption_algorithm_t alg,
							size_t key_size, chunk_t iv, chunk_t passphrase)
{
	hasher_t *hasher;
	crypter_t *crypter;
	chunk_t salt = { iv.ptr, PKCS5_SALT_LEN };
	chunk_t hash;
	chunk_t decrypted;
	chunk_t key = {alloca(key_size), key_size};
	u_int8_t padding, *last_padding_pos, *first_padding_pos;

	/* build key from passphrase and IV */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	if (hasher == NULL)
	{
		DBG1("  MD5 hash algorithm not available");
		return NOT_SUPPORTED;
	}
	hash.len = hasher->get_hash_size(hasher);
	hash.ptr = alloca(hash.len);
	hasher->get_hash(hasher, passphrase, NULL);
	hasher->get_hash(hasher, salt, hash.ptr);
	memcpy(key.ptr, hash.ptr, hash.len);

	if (key.len > hash.len)
	{
		hasher->get_hash(hasher, hash, NULL);
		hasher->get_hash(hasher, passphrase, NULL);
		hasher->get_hash(hasher, salt, hash.ptr);
		memcpy(key.ptr + hash.len, hash.ptr, key.len - hash.len);
	}
	hasher->destroy(hasher);

	/* decrypt blob */
	crypter = lib->crypto->create_crypter(lib->crypto, alg, key_size);
	if (crypter == NULL)
	{
		DBG1("  %N encryption algorithm not available",
			 encryption_algorithm_names, alg);
		return NOT_SUPPORTED;
	}
	crypter->set_key(crypter, key);

	if (iv.len != crypter->get_block_size(crypter) ||
		blob->len % iv.len)
	{
		crypter->destroy(crypter);
		DBG1("  data size is not multiple of block size");
		return PARSE_ERROR;
	}
	crypter->decrypt(crypter, *blob, iv, &decrypted);
	crypter->destroy(crypter);
	memcpy(blob->ptr, decrypted.ptr, blob->len);
	chunk_free(&decrypted);

	/* determine amount of padding */
	last_padding_pos = blob->ptr + blob->len - 1;
	padding = *last_padding_pos;
	if (padding > blob->len)
	{
		first_padding_pos = blob->ptr;
	}
	else
	{
		first_padding_pos = last_padding_pos - padding;
	}
	/* check the padding pattern */
	while (--last_padding_pos > first_padding_pos)
	{
		if (*last_padding_pos != padding)
		{
			DBG1("  invalid passphrase");
			return INVALID_ARG;
		}
	}
	/* remove padding */
	blob->len -= padding;
	return SUCCESS;
}

/**
 * Converts a PEM encoded file into its binary form (RFC 1421, RFC 934)
 */
status_t pem_to_bin(chunk_t *blob, private_builder_t *this, bool *pgp)
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
	chunk_t line   = chunk_empty;
	chunk_t iv     = chunk_empty;
	chunk_t passphrase;
	int try = 0;
	u_char iv_buf[HASH_SIZE_MD5];

	dst.len = 0;
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
				state = PEM_HEADER;
				if (memchr(line.ptr, ':', line.len) == NULL)
				{
					state = PEM_BODY;
				}
			}
			if (state == PEM_HEADER)
			{
				err_t ugh = NULL;
				chunk_t name  = chunk_empty;
				chunk_t value = chunk_empty;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0)
				{
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a parameter: value pair */
				DBG2("  %.*s", (int)line.len, line.ptr);
				ugh = extract_parameter_value(&name, &value, &line);
				if (ugh != NULL)
				{
					continue;
				}
				if (match("Proc-Type", &name) && *value.ptr == '4')
				{
					encrypted = TRUE;
				}
				else if (match("DEK-Info", &name))
				{
					chunk_t dek;

					if (!extract_token(&dek, ',', &value))
					{
						dek = value;
					}
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
						DBG1("  encryption algorithm '%.*s' not supported",
							 dek.len, dek.ptr);
						return NOT_SUPPORTED;
					}
					eat_whitespace(&value);
					iv = chunk_from_hex(value, iv.ptr);
				}
			}
			else /* state is PEM_BODY */
			{
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
					DBG2("  armor checksum: %.*s", (int)data.len, data.ptr);
					continue;
				}

				if (blob->len - dst.len < data.len / 4 * 3)
				{
					state = PEM_ABORT;
				}
				data = chunk_from_base64(data, dst.ptr);

				dst.ptr += data.len;
				dst.len += data.len;
			}
		}
	}
	/* set length to size of binary blob */
	blob->len = dst.len;

	if (state != PEM_POST)
	{
		DBG1("  file coded in unknown format, discarded");
		return PARSE_ERROR;
	}
	if (!encrypted)
	{
		return SUCCESS;
	}
	if (!this->cb)
	{
		DBG1("  missing passphrase");
		return INVALID_ARG;
	}
	while (TRUE)
	{
		passphrase = this->cb(this->data, ++try);
		if (!passphrase.len || !passphrase.ptr)
		{
			return INVALID_ARG;
		}
		switch (pem_decrypt(blob, alg, key_size, iv, passphrase))
		{
			case INVALID_ARG:
				/* bad passphrase, retry */
				continue;
			case SUCCESS:
				return SUCCESS;
			default:
				return FAILED;
		}
	}
}

/**
 * build the credential from a blob
 */
static void *build_from_blob(private_builder_t *this, chunk_t blob)
{
	void *cred = NULL;
	bool pgp = FALSE;

	blob = chunk_clone(blob);
	if (!is_asn1(blob))
	{
		if (pem_to_bin(&blob, this, &pgp) != SUCCESS)
		{
			chunk_clear(&blob);
			return NULL;
		}
		if (pgp && this->type == CRED_PRIVATE_KEY)
		{
			/* PGP encoded keys are parsed with a KEY_ANY key type, as it
			 * can contain any type of key. However, ipsec.secrets uses
			 * RSA for PGP keys, which is actually wrong. */
			this->subtype = KEY_ANY;
		}
	}
	cred = lib->creds->create(lib->creds, this->type, this->subtype,
							  pgp ? BUILD_BLOB_PGP : BUILD_BLOB_ASN1_DER, blob,
							  this->flags ? BUILD_X509_FLAG : BUILD_END,
							  this->flags, BUILD_END);
	chunk_clear(&blob);
	return cred;
}

/**
 * build the credential from a file
 */
static void *build_from_file(private_builder_t *this, char *file)
{
	void *cred = NULL;
	struct stat sb;
	void *addr;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1("  opening '%s' failed: %s", file, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &sb) == -1)
	{
		DBG1("  getting file size of '%s' failed: %s", file, strerror(errno));
		close(fd);
		return NULL;
	}

	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
	{
		DBG1("  mapping '%s' failed: %s", file, strerror(errno));
		close(fd);
		return NULL;
	}

	cred = build_from_blob(this, chunk_create(addr, sb.st_size));

	munmap(addr, sb.st_size);
	close(fd);
	return cred;
}

/**
 * build the credential from a file
 */
static void *build_from_fd(private_builder_t *this, int fd)
{
	char buf[8096];
	char *pos = buf;
	ssize_t len, total = 0;

	while (TRUE)
	{
		len = read(fd, pos, buf + sizeof(buf) - pos);
		if (len < 0)
		{
			DBG1("reading from file descriptor failed: %s", strerror(errno));
			return NULL;
		}
		if (len == 0)
		{
			break;
		}
		total += len;
		if (total == sizeof(buf))
		{
			DBG1("buffer too small to read from file descriptor");
			return NULL;
		}
	}
	return build_from_blob(this, chunk_create(buf, total));
}

/**
 * Implementation of builder_t.build
 */
static void *build(private_builder_t *this)
{
	void *cred = NULL;

	if (this->pem.ptr)
	{
		cred = build_from_blob(this, this->pem);
	}
	else if (this->file)
	{
		cred = build_from_file(this, this->file);
	}
	else if (this->fd != -1)
	{
		cred = build_from_fd(this, this->fd);
	}
	free(this);
	return cred;
}

/**
 * passphrase callback to use if passphrase given
 */
static chunk_t given_passphrase_cb(chunk_t *passphrase, int try)
{
	if (try > 1)
	{	/* try only once for given passphrases */
		return chunk_empty;
	}
	return *passphrase;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;

	switch (part)
	{
		case BUILD_FROM_FILE:
			va_start(args, part);
			this->file = va_arg(args, char*);
			va_end(args);
			break;
		case BUILD_FROM_FD:
			va_start(args, part);
			this->fd = va_arg(args, int);
			va_end(args);
			break;
		case BUILD_BLOB_PEM:
			va_start(args, part);
			this->pem = va_arg(args, chunk_t);
			va_end(args);
			break;
		case BUILD_PASSPHRASE:
			va_start(args, part);
			this->passphrase = va_arg(args, chunk_t);
			va_end(args);
			if (this->passphrase.len && this->passphrase.ptr)
			{
				this->cb = (void*)given_passphrase_cb;
				this->data = &this->passphrase;
			}
			break;
		case BUILD_PASSPHRASE_CALLBACK:
			va_start(args, part);
			this->cb = va_arg(args, chunk_t(*)(void*,int));
			this->data = va_arg(args, void*);
			va_end(args);
			break;
		case BUILD_X509_FLAG:
			va_start(args, part);
			this->flags = va_arg(args, int);
			va_end(args);
			break;
		default:
			builder_cancel(&this->public);
			break;
	}
}

/**
 * Generic PEM builder.
 */
static builder_t *pem_builder(credential_type_t type, int subtype)
{
	private_builder_t *this = malloc_thing(private_builder_t);

	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;

	this->type = type;
	this->subtype = subtype;
	this->file = NULL;
	this->fd = -1;
	this->pem = chunk_empty;
	this->passphrase = chunk_empty;
	this->cb = NULL;
	this->data = NULL;
	this->flags = 0;

	return &this->public;
}

/**
 * Private key PEM builder.
 */
builder_t *private_key_pem_builder(key_type_t type)
{
	return pem_builder(CRED_PRIVATE_KEY, type);
}

/**
 * Public key PEM builder.
 */
builder_t *public_key_pem_builder(key_type_t type)
{
	return pem_builder(CRED_PUBLIC_KEY, type);
}

/**
 * Certificate PEM builder.
 */
builder_t *certificate_pem_builder(certificate_type_t type)
{
	return pem_builder(CRED_CERTIFICATE, type);
}

