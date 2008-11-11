/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "agent_private_key.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>

#include <library.h>
#include <chunk.h>
#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif /* UNIX_PATH_MAX */

typedef struct private_agent_private_key_t private_agent_private_key_t;
typedef enum agent_msg_type_t agent_msg_type_t;

/**
 * Private data of a agent_private_key_t object.
 */
struct private_agent_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	agent_private_key_t public;
	
	/**
	 * ssh-agent unix socket connection
	 */
	int socket;
	
	/**
	 * key identity blob in ssh format
	 */
	chunk_t key;
	
	/**
	 * keysize in bytes
	 */
	size_t key_size;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKey object
	 */
	identification_t* keyid;

	/**
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	identification_t* keyid_info;
	
	/**
	 * reference count
	 */
	refcount_t ref;	
};

/**
 * Message types for ssh-agent protocol
 */
enum agent_msg_type_t {
	SSH_AGENT_FAILURE = 5,
	SSH_AGENT_SUCCESS =	6,
	SSH_AGENT_ID_REQUEST = 11,
	SSH_AGENT_ID_RESPONSE = 12,
	SSH_AGENT_SIGN_REQUEST = 13,
	SSH_AGENT_SIGN_RESPONSE = 14,
};

/**
 * read a byte from a blob
 */
static u_char read_byte(chunk_t *blob)
{
	u_char val;

	if (blob->len < sizeof(u_char))
	{
		return 0;
	}
	val = *(blob->ptr);
	*blob = chunk_skip(*blob, sizeof(u_char));
	return val;
}

/**
 * read a u_int32_t from a blob
 */
static u_int32_t read_uint32(chunk_t *blob)
{
	u_int32_t val;

	if (blob->len < sizeof(u_int32_t))
	{
		return 0;
	}
	val = ntohl(*(u_int32_t*)blob->ptr);
	*blob = chunk_skip(*blob, sizeof(u_int32_t));
	return val;
}

/**
 * read a ssh-agent "string" length/value from a blob
 */
static chunk_t read_string(chunk_t *blob)
{
	int len;
	chunk_t str;
	
	len = read_uint32(blob);
	if (len > blob->len)
	{
		return chunk_empty;
	}
	str = chunk_create(blob->ptr, len);
	*blob = chunk_skip(*blob, + len);
	return str;
}

/**
 * open socket connection to the ssh-agent
 */
static int open_connection(char *path)
{
	struct sockaddr_un addr;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
	{
		DBG1("opening ssh-agent socket %s failed: %s:", path, strerror(errno));
		return -1;
	}
	
	addr.sun_family = AF_UNIX;
	addr.sun_path[UNIX_PATH_MAX - 1] = '\0';
	strncpy(addr.sun_path, path, UNIX_PATH_MAX - 1);
	
	if (connect(s, (struct sockaddr*)&addr, SUN_LEN(&addr)) != 0)
	{
		DBG1("connecting to ssh-agent socket failed: %s", strerror(errno));
		close(s);
		return -1;
	}
	return s;
}

/**
 * check if the ssh agent key blob matches to our public key
 */
static bool matches_pubkey(chunk_t key, public_key_t *pubkey)
{
	chunk_t pubkeydata, hash, n, e;
	hasher_t *hasher;
	identification_t *id;
	bool match;
	
	if (!pubkey)
	{
		return TRUE;
	}
	read_string(&key);
	e = read_string(&key);
	n = read_string(&key);
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		return FALSE;
	}
	pubkeydata = asn1_wrap(ASN1_SEQUENCE, "mm", 
						asn1_wrap(ASN1_INTEGER, "c", n),
						asn1_wrap(ASN1_INTEGER, "c", e));
	hasher->allocate_hash(hasher, pubkeydata, &hash);
	free(pubkeydata.ptr);
	id = pubkey->get_id(pubkey, ID_PUBKEY_SHA1);
	if (!id)
	{
		return FALSE;
	}
	match = chunk_equals(id->get_encoding(id), hash);
	free(hash.ptr);
	return match;
}

/** 
 * Get the first usable key from the agent
 */
static bool read_key(private_agent_private_key_t *this, public_key_t *pubkey)
{
	int len, count;
	char buf[2048];
	chunk_t blob = chunk_from_buf(buf), key, type, tmp;
	
	len = htonl(1);
	buf[0] = SSH_AGENT_ID_REQUEST;
	if (write(this->socket, &len, sizeof(len)) != sizeof(len) ||
		write(this->socket, &buf, 1) != 1)
	{
		DBG1("writing to ssh-agent failed");
		return FALSE;
	}
	
	blob.len = read(this->socket, blob.ptr, blob.len);
	
	if (blob.len < sizeof(u_int32_t) + sizeof(u_char) ||
		read_uint32(&blob) != blob.len ||
		read_byte(&blob) != SSH_AGENT_ID_RESPONSE)
	{
		DBG1("received invalid ssh-agent identity response");
		return FALSE;
	}
	count = read_uint32(&blob);
	
	while (blob.len)
	{
		key = read_string(&blob);
		if (key.len)
		{
			tmp = key;
			type = read_string(&tmp);
			read_string(&tmp);
			tmp = read_string(&tmp);
			if (type.len && strneq("ssh-rsa", type.ptr, type.len) &&
				tmp.len >= 512/8 && matches_pubkey(key, pubkey))
			{
				this->key = chunk_clone(key);
				this->key_size = tmp.len;
				if (tmp.ptr[0] == 0)
				{
					this->key_size--;
				}
				return TRUE;
			}
			continue;
		}
		break;
	}
	return FALSE;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static bool sign(private_agent_private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *signature)
{
	u_int32_t len, flags;
	char buf[2048];
	chunk_t blob = chunk_from_buf(buf);
	
	if (scheme != SIGN_DEFAULT && scheme != SIGN_RSA_EMSA_PKCS1_SHA1)
	{
		DBG1("signature scheme %N not supported by ssh-agent",
			 signature_scheme_names, scheme);
		return FALSE;
	}
	
	len = htonl(1 + sizeof(u_int32_t) * 3 + this->key.len + data.len);
	buf[0] = SSH_AGENT_SIGN_REQUEST;
	if (write(this->socket, &len, sizeof(len)) != sizeof(len) ||
		write(this->socket, &buf, 1) != 1)
	{
		DBG1("writing to ssh-agent failed");
		return FALSE;
	}
	
	len = htonl(this->key.len);
	if (write(this->socket, &len, sizeof(len)) != sizeof(len) ||
		write(this->socket, this->key.ptr, this->key.len) != this->key.len)
	{
		DBG1("writing to ssh-agent failed");
		return FALSE;
	}
	
	len = htonl(data.len);
	if (write(this->socket, &len, sizeof(len)) != sizeof(len) ||
		write(this->socket, data.ptr, data.len) != data.len)
	{
		DBG1("writing to ssh-agent failed");
		return FALSE;
	}
	
	flags = htonl(0);
	if (write(this->socket, &flags, sizeof(flags)) != sizeof(flags))
	{
		DBG1("writing to ssh-agent failed");
		return FALSE;
	}
	
	blob.len = read(this->socket, blob.ptr, blob.len);
	if (blob.len < sizeof(u_int32_t) + sizeof(u_char) ||
		read_uint32(&blob) != blob.len ||
		read_byte(&blob) != SSH_AGENT_SIGN_RESPONSE)
	{
		DBG1("received invalid ssh-agent signature response");
		return FALSE;
	}
	/* parse length */
	blob = read_string(&blob);
	/* skip sig type */
	read_string(&blob);
	/* parse length */
	blob = read_string(&blob);
	if (!blob.len)
	{
		DBG1("received invalid ssh-agent signature response");
		return FALSE;
	}
	*signature =  chunk_clone(blob);
	return TRUE;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static key_type_t get_type(private_agent_private_key_t *this)
{
	return KEY_RSA;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static bool decrypt(private_agent_private_key_t *this,
					chunk_t crypto, chunk_t *plain)
{
	DBG1("private key decryption not supported by ssh-agent");
	return FALSE;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static size_t get_keysize(private_agent_private_key_t *this)
{
	return this->key_size;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static identification_t* get_id(private_agent_private_key_t *this,
								id_type_t type)
{
	switch (type)
	{
		case ID_PUBKEY_INFO_SHA1:
			return this->keyid_info;
		case ID_PUBKEY_SHA1:
			return this->keyid;
		default:
			return NULL;
	}
}

/**
 * Implementation of agent_private_key.get_public_key.
 */
static public_key_t* get_public_key(private_agent_private_key_t *this)
{
	chunk_t key, n, e, encoded;
	public_key_t *public;
	
	key = this->key;
	read_string(&key);
	e = read_string(&key);
	n = read_string(&key);
	encoded = asn1_wrap(ASN1_SEQUENCE, "mm", 
					asn1_wrap(ASN1_INTEGER, "c", n),
					asn1_wrap(ASN1_INTEGER, "c", e));

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA, 
								BUILD_BLOB_ASN1_DER, encoded, BUILD_END);
	free(encoded.ptr);
	return public;
}

/**
 * Implementation of agent_private_key.belongs_to.
 */
static bool belongs_to(private_agent_private_key_t *this, public_key_t *public)
{
	identification_t *keyid;

	if (public->get_type(public) != KEY_RSA)
	{
		return FALSE;
	}
	keyid = public->get_id(public, ID_PUBKEY_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid))
	{
		return TRUE;
	}
	keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid_info))
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Build the RSA key identifier from n and e using SHA1 hashed publicKey(Info).
 */
static bool build_ids(private_agent_private_key_t *this)
{
	chunk_t publicKeyInfo, publicKey, hash, key, n, e;
	hasher_t *hasher;
	
	key = this->key;
	read_string(&key);
	e = read_string(&key);
	n = read_string(&key);
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		DBG1("SHA1 hash algorithm not supported, unable to use RSA");
		return FALSE;
	}
	publicKey = asn1_wrap(ASN1_SEQUENCE, "mm", 
					asn1_wrap(ASN1_INTEGER, "c", n),
					asn1_wrap(ASN1_INTEGER, "c", e));
	hasher->allocate_hash(hasher, publicKey, &hash);
	this->keyid = identification_create_from_encoding(ID_PUBKEY_SHA1, hash);
	chunk_free(&hash);
	
	publicKeyInfo = asn1_wrap(ASN1_SEQUENCE, "cm",
						asn1_algorithmIdentifier(OID_RSA_ENCRYPTION),
						asn1_bitstring("m", publicKey));
	hasher->allocate_hash(hasher, publicKeyInfo, &hash);
	this->keyid_info = identification_create_from_encoding(ID_PUBKEY_INFO_SHA1, hash);
	chunk_free(&hash);
	
	hasher->destroy(hasher);
	chunk_free(&publicKeyInfo);
	return TRUE;
}

/**
 * Implementation of private_key_t.get_encoding.
 */
static chunk_t get_encoding(private_agent_private_key_t *this)
{
	return chunk_empty;
}

/**
 * Implementation of agent_private_key.get_ref.
 */
static private_agent_private_key_t* get_ref(private_agent_private_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of agent_private_key.destroy.
 */
static void destroy(private_agent_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		close(this->socket);
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		free(this->key.ptr);
		free(this);
	}
}

/**
 * Internal constructor
 */
static agent_private_key_t *agent_private_key_create(char *path,
													 public_key_t *pubkey)
{
	private_agent_private_key_t *this = malloc_thing(private_agent_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(private_key_t *this))get_type;
	this->public.interface.sign = (bool (*)(private_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t *signature))sign;
	this->public.interface.decrypt = (bool (*)(private_key_t *this, chunk_t crypto, chunk_t *plain))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (private_key_t *this,id_type_t))get_id;
	this->public.interface.get_public_key = (public_key_t* (*)(private_key_t *this))get_public_key;
	this->public.interface.belongs_to = (bool (*) (private_key_t *this, public_key_t *public))belongs_to;
	this->public.interface.get_encoding = (chunk_t(*)(private_key_t*))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*)(private_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(private_key_t *this))destroy;
	
	this->socket = open_connection(path);
	if (this->socket < 0)
	{
		free(this);
		return NULL;
	}
	this->key = chunk_empty;
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	if (!read_key(this, pubkey) || !build_ids(this))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading/generation
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** agent unix socket */
	char *socket;
	/** matching public key */
	public_key_t *pubkey;
};

/**
 * Implementation of builder_t.build
 */
static agent_private_key_t *build(private_builder_t *this)
{
	agent_private_key_t *key = NULL;
	
	if (this->socket)
	{
		key = agent_private_key_create(this->socket, this->pubkey);
	}
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	switch (part)
	{
		case BUILD_AGENT_SOCKET:
		{
			va_start(args, part);
			this->socket = va_arg(args, char*);
			va_end(args);
			return;
		}
		case BUILD_PUBLIC_KEY:
		{
			va_start(args, part);
			this->pubkey = va_arg(args, public_key_t*);
			va_end(args);
			return;
		}
		default:
			break;
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *agent_private_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_RSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->pubkey = NULL;
	this->socket = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

