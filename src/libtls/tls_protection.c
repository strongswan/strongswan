/*
 * Copyright (C) 2010 Martin Willi
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

#include "tls_protection.h"

#include <utils/debug.h>

typedef struct private_tls_protection_t private_tls_protection_t;

/**
 * Private data of an tls_protection_t object.
 */
struct private_tls_protection_t {

	/**
	 * Public tls_protection_t interface.
	 */
	tls_protection_t public;

	/**
	 * negotiated TLS version
	 */
	tls_version_t version;

	/**
	 * Upper layer, TLS record compression
	 */
	tls_compression_t *compression;

	/**
	 * TLS alert handler
	 */
	tls_alert_t *alert;

	/**
	 * RNG if we generate IVs ourself
	 */
	rng_t *rng;

	/**
	 * Sequence number of incoming records
	 */
	u_int32_t seq_in;

	/**
	 * Sequence number for outgoing records
	 */
	u_int32_t seq_out;

	/**
	 * Signer instance for inbound traffic
	 */
	signer_t *signer_in;

	/**
	 * Signer instance for outbound traffic
	 */
	signer_t *signer_out;

	/**
	 * Crypter instance for inbound traffic
	 */
	crypter_t *crypter_in;

	/**
	 * Crypter instance for outbound traffic
	 */
	crypter_t *crypter_out;

	/**
	 * Current IV for input decryption
	 */
	chunk_t iv_in;

	/**
	 * Current IV for output decryption
	 */
	chunk_t iv_out;
};

/**
 * Create the header and feed it into a signer for MAC verification
 */
static bool sigheader(signer_t *signer, u_int32_t seq, u_int8_t type,
					  u_int16_t version, u_int16_t length)
{
	/* we only support 32 bit sequence numbers, but TLS uses 64 bit */
	struct __attribute__((__packed__)) {
		u_int32_t seq_high;
		u_int32_t seq_low;
		u_int8_t type;
		u_int16_t version;
		u_int16_t length;
	} header = {
		.type = type,
	};
	htoun32(&header.seq_low, seq);
	htoun16(&header.version, version);
	htoun16(&header.length, length);

	return signer->get_signature(signer, chunk_from_thing(header), NULL);
}

METHOD(tls_protection_t, process, status_t,
	private_tls_protection_t *this, tls_content_type_t type, chunk_t data)
{
	if (this->alert->fatal(this->alert))
	{	/* don't accept more input, fatal error occurred */
		return NEED_MORE;
	}

	if (this->crypter_in)
	{
		chunk_t iv, next_iv = chunk_empty;
		u_int8_t bs, padding_length;

		bs = this->crypter_in->get_block_size(this->crypter_in);
		if (this->iv_in.len)
		{	/* < TLSv1.1 uses IV from key derivation/last block */
			if (data.len < bs || data.len % bs)
			{
				DBG1(DBG_TLS, "encrypted TLS record length invalid");
				this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
				return NEED_MORE;
			}
			iv = this->iv_in;
			next_iv = chunk_clone(chunk_create(data.ptr + data.len - bs, bs));
		}
		else
		{	/* TLSv1.1 uses random IVs, prepended to record */
			iv.len = this->crypter_in->get_iv_size(this->crypter_in);
			iv = chunk_create(data.ptr, iv.len);
			data = chunk_skip(data, iv.len);
			if (data.len < bs || data.len % bs)
			{
				DBG1(DBG_TLS, "encrypted TLS record length invalid");
				this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
				return NEED_MORE;
			}
		}
		if (!this->crypter_in->decrypt(this->crypter_in, data, iv, NULL))
		{
			free(next_iv.ptr);
			this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
			return NEED_MORE;
		}

		if (next_iv.len)
		{	/* next record IV is last ciphertext block of this record */
			memcpy(this->iv_in.ptr, next_iv.ptr, next_iv.len);
			free(next_iv.ptr);
		}

		padding_length = data.ptr[data.len - 1];
		if (padding_length < data.len)
		{	/* remove padding if it looks valid. Continue with no padding, try
			 * to prevent timing attacks. */
			data.len -= padding_length + 1;
		}
	}
	if (this->signer_in)
	{
		chunk_t mac;
		u_int8_t bs;

		bs = this->signer_in->get_block_size(this->signer_in);
		if (data.len < bs)
		{
			DBG1(DBG_TLS, "TLS record too short to verify MAC");
			this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
			return NEED_MORE;
		}
		mac = chunk_skip(data, data.len - bs);
		data.len -= bs;

		if (!sigheader(this->signer_in, this->seq_in, type,
					   this->version, data.len) ||
			!this->signer_in->verify_signature(this->signer_in, data, mac))
		{
			DBG1(DBG_TLS, "TLS record MAC verification failed");
			this->alert->add(this->alert, TLS_FATAL, TLS_BAD_RECORD_MAC);
			return NEED_MORE;
		}
	}

	if (type == TLS_CHANGE_CIPHER_SPEC)
	{
		this->seq_in = 0;
	}
	else
	{
		this->seq_in++;
	}
	return this->compression->process(this->compression, type, data);
}

METHOD(tls_protection_t, build, status_t,
	private_tls_protection_t *this, tls_content_type_t *type, chunk_t *data)
{
	status_t status;

	status = this->compression->build(this->compression, type, data);
	if (*type == TLS_CHANGE_CIPHER_SPEC)
	{
		this->seq_out = 0;
		return status;
	}

	if (status == NEED_MORE)
	{
		if (this->signer_out)
		{
			chunk_t mac;

			if (!sigheader(this->signer_out, this->seq_out, *type,
						   this->version, data->len) ||
				!this->signer_out->allocate_signature(this->signer_out,
						   *data, &mac))
			{
				return FAILED;
			}
			if (this->crypter_out)
			{
				chunk_t padding, iv;
				u_int8_t bs, padding_length;

				bs = this->crypter_out->get_block_size(this->crypter_out);
				padding_length = bs - ((data->len + mac.len + 1) % bs);

				padding = chunk_alloca(padding_length);
				memset(padding.ptr, padding_length, padding.len);

				if (this->iv_out.len)
				{	/* < TLSv1.1 uses IV from key derivation/last block */
					iv = this->iv_out;
				}
				else
				{	/* TLSv1.1 uses random IVs, prepended to record */
					iv.len = this->crypter_out->get_iv_size(this->crypter_out);
					if (!this->rng ||
						!this->rng->allocate_bytes(this->rng, iv.len, &iv))
					{
						DBG1(DBG_TLS, "failed to generate TLS IV");
						free(data->ptr);
						return FAILED;
					}
				}

				*data = chunk_cat("mmcc", *data, mac, padding,
								  chunk_from_thing(padding_length));
				/* encrypt inline */
				if (!this->crypter_out->encrypt(this->crypter_out, *data,
												iv, NULL))
				{
					if (!this->iv_out.len)
					{
						free(iv.ptr);
					}
					free(data->ptr);
					return FAILED;
				}

				if (this->iv_out.len)
				{	/* next record IV is last ciphertext block of this record */
					memcpy(this->iv_out.ptr, data->ptr + data->len -
						   this->iv_out.len, this->iv_out.len);
				}
				else
				{	/* prepend IV */
					*data = chunk_cat("mm", iv, *data);
				}
			}
			else
			{	/* NULL encryption */
				*data = chunk_cat("mm", *data, mac);
			}
		}
		this->seq_out++;
	}
	return status;
}

METHOD(tls_protection_t, set_cipher, void,
	private_tls_protection_t *this, bool inbound, signer_t *signer,
	crypter_t *crypter, chunk_t iv)
{
	if (inbound)
	{
		this->signer_in = signer;
		this->crypter_in = crypter;
		this->iv_in = iv;
	}
	else
	{
		this->signer_out = signer;
		this->crypter_out = crypter;
		this->iv_out = iv;
		if (!iv.len)
		{	/* generate IVs if none given */
			this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		}
	}
}

METHOD(tls_protection_t, set_version, void,
	private_tls_protection_t *this, tls_version_t version)
{
	this->version = version;
}

METHOD(tls_protection_t, destroy, void,
	private_tls_protection_t *this)
{
	DESTROY_IF(this->rng);
	free(this);
}

/**
 * See header
 */
tls_protection_t *tls_protection_create(tls_compression_t *compression,
										tls_alert_t *alert)
{
	private_tls_protection_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.set_cipher = _set_cipher,
			.set_version = _set_version,
			.destroy = _destroy,
		},
		.alert = alert,
		.compression = compression,
	);

	return &this->public;
}
