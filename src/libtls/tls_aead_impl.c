/*
 * Copyright (C) 2014 Martin Willi
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

#include "tls_aead.h"

typedef struct private_tls_aead_t private_tls_aead_t;

/**
 * Private data of an tls_aead_t object.
 */
struct private_tls_aead_t {

	/**
	 * Public tls_aead_t interface.
	 */
	tls_aead_t public;

	/**
	 * traditional crypter
	 */
	crypter_t *crypter;

	/**
	 * traditional signer
	 */
	signer_t *signer;

	/**
	 * Next implicit IV
	 */
	chunk_t iv;
};

/**
 * Associated header data to create signature over
 */
typedef struct __attribute__((__packed__)) {
	uint64_t seq;
	uint8_t type;
	uint16_t version;
	uint16_t length;
} sigheader_t;

METHOD(tls_aead_t, encrypt, bool,
	private_tls_aead_t *this, tls_version_t version,
	tls_content_type_t *type, uint64_t seq, chunk_t *data)
{
	chunk_t assoc, mac, padding;
	uint8_t bs, padlen;
	sigheader_t hdr;

	hdr.type = *type;
	htoun64(&hdr.seq, seq);
	htoun16(&hdr.version, version);
	htoun16(&hdr.length, data->len);

	assoc = chunk_from_thing(hdr);
	if (!this->signer->get_signature(this->signer, assoc, NULL) ||
		!this->signer->allocate_signature(this->signer, *data, &mac))
	{
		return FALSE;
	}
	bs = this->crypter->get_block_size(this->crypter);
	padlen = pad_len(data->len + mac.len + 1, bs);

	padding = chunk_alloca(padlen);
	memset(padding.ptr, padlen, padding.len);

	*data = chunk_cat("mmcc", *data, mac, padding, chunk_from_thing(padlen));
	/* encrypt inline */
	if (!this->crypter->encrypt(this->crypter, *data, this->iv, NULL))
	{
		return FALSE;
	}
	if (data->len < this->iv.len)
	{
		return FALSE;
	}
	/* next record IV is last ciphertext block of this record */
	memcpy(this->iv.ptr, data->ptr + data->len - this->iv.len, this->iv.len);
	return TRUE;
}

METHOD(tls_aead_t, decrypt, bool,
	private_tls_aead_t *this, tls_version_t version,
	tls_content_type_t *type, uint64_t seq, chunk_t *data)
{
	chunk_t assoc, mac, iv;
	uint8_t bs, padlen, valid;
	sigheader_t hdr;
	size_t i;

	bs = this->crypter->get_block_size(this->crypter);
	if (data->len < bs || data->len < this->iv.len || data->len % bs)
	{
		return FALSE;
	}
	iv = chunk_alloca(this->iv.len);
	memcpy(iv.ptr, this->iv.ptr, this->iv.len);
	memcpy(this->iv.ptr, data->ptr + data->len - this->iv.len, this->iv.len);
	if (!this->crypter->decrypt(this->crypter, *data, iv, NULL))
	{
		return FALSE;
	}
	/* check and remove padding in constant time */
	padlen = data->ptr[data->len - 1];
	valid = constant_time_lt64(padlen, data->len);
	for (i = 1; i < min(data->len, 256); i++)
	{
		/* ignore comparison for bytes outside of padding */
		valid &= constant_time_lt(padlen, i) |
				 constant_time_eq(data->ptr[data->len - 1 - i], padlen);
	}
	data->len = constant_time_select64(data->len - padlen - 1, data->len, valid);

	/* make sure to always verify a MAC value */
	bs = this->signer->get_block_size(this->signer);
	valid &= constant_time_ge64(data->len, bs);
	data->len = constant_time_select64(data->len - bs, data->len, valid);

	mac = chunk_alloca(bs);
	memset(mac.ptr, 0, mac.len);
	memcpy(mac.ptr, data->ptr + constant_time_select64(data->len, 0, valid),
		   constant_time_select(mac.len, min(mac.len, data->len), valid));

	hdr.type = *type;
	htoun64(&hdr.seq, seq);
	htoun16(&hdr.version, version);
	htoun16(&hdr.length, data->len);

	assoc = chunk_from_thing(hdr);
	if (!this->signer->get_signature(this->signer, assoc, NULL) ||
		!this->signer->verify_signature(this->signer, *data, mac))
	{
		return FALSE;
	}
	return valid;
}

METHOD(tls_aead_t, get_mac_key_size, size_t,
	private_tls_aead_t *this)
{
	return this->signer->get_key_size(this->signer);
}

METHOD(tls_aead_t, get_encr_key_size, size_t,
	private_tls_aead_t *this)
{
	return this->crypter->get_key_size(this->crypter);
}

METHOD(tls_aead_t, get_iv_size, size_t,
	private_tls_aead_t *this)
{
	return this->iv.len;
}

METHOD(tls_aead_t, set_keys, bool,
	private_tls_aead_t *this, chunk_t mac, chunk_t encr, chunk_t iv)
{
	if (iv.len != this->iv.len)
	{
		return FALSE;
	}
	memcpy(this->iv.ptr, iv.ptr, this->iv.len);
	return this->signer->set_key(this->signer, mac) &&
		   this->crypter->set_key(this->crypter, encr);
}

METHOD(tls_aead_t, destroy, void,
	private_tls_aead_t *this)
{
	DESTROY_IF(this->crypter);
	DESTROY_IF(this->signer);
	chunk_free(&this->iv);
	free(this);
}

/**
 * See header
 */
tls_aead_t *tls_aead_create_implicit(integrity_algorithm_t mac,
								encryption_algorithm_t encr, size_t encr_size)
{
	private_tls_aead_t *this;

	INIT(this,
		.public = {
			.encrypt = _encrypt,
			.decrypt = _decrypt,
			.get_mac_key_size = _get_mac_key_size,
			.get_encr_key_size = _get_encr_key_size,
			.get_iv_size = _get_iv_size,
			.set_keys = _set_keys,
			.destroy = _destroy,
		},
		.crypter = lib->crypto->create_crypter(lib->crypto, encr, encr_size),
		.signer = lib->crypto->create_signer(lib->crypto, mac),
	);

	if (!this->crypter || !this->signer)
	{
		destroy(this);
		return NULL;
	}

	this->iv = chunk_alloc(this->crypter->get_iv_size(this->crypter));

	return &this->public;
}
