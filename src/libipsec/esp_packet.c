/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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


#include "esp_packet.h"

#include <library.h>
#include <debug.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <bio/bio_reader.h>
#include <bio/bio_writer.h>

#include <netinet/in.h>

typedef struct private_esp_packet_t private_esp_packet_t;

/**
 * Private additions to esp_packet_t.
 */
struct private_esp_packet_t {

	/**
	 * Public members
	 */
	esp_packet_t public;

	/**
	 * Source address
	 */
	host_t *src;

	/**
	 * Destination address
	 */
	host_t *dst;

	/**
	 * Payload of this packet
	 */
	chunk_t payload;

	/**
	 * Next Header info (e.g. IPPROTO_IPIP)
	 */
	u_int8_t next_header;

	/**
	 * Raw packet data
	 */
	chunk_t packet_data;
};

METHOD(esp_packet_t, parse_header, bool,
	private_esp_packet_t *this, u_int32_t *spi)
{
	bio_reader_t *reader;
	u_int32_t seq;

	reader = bio_reader_create(this->packet_data);
	if (!reader->read_uint32(reader, spi) ||
		!reader->read_uint32(reader, &seq))
	{
		DBG1(DBG_ESP, "failed to parse ESP header: invalid length");
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);

	DBG2(DBG_ESP, "parsed ESP header with SPI %.8x [seq %u]", *spi, seq);
	*spi = htonl(*spi);
	return TRUE;
}

/**
 * Check padding as specified in RFC 4303
 */
static bool check_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		if (padding.ptr[i] != (u_int8_t)(i + 1))
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Remove the padding from the payload and set the next header info
 */
static bool remove_padding(private_esp_packet_t *this)
{
	u_int8_t next_header, pad_length;
	chunk_t padding;
	bio_reader_t *reader;

	reader = bio_reader_create(this->payload);
	if (!reader->read_uint8_end(reader, &next_header) ||
		!reader->read_uint8_end(reader, &pad_length))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid length");
		reader->destroy(reader);
		return FALSE;
	}
	if (!reader->read_data_end(reader, pad_length, &padding) ||
		!check_padding(padding))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid padding");
		reader->destroy(reader);
		return FALSE;
	}
	this->payload = reader->peek(reader);
	this->next_header = next_header;
	reader->destroy(reader);

	DBG3(DBG_ESP, "ESP payload:\n  payload %B\n  padding %B\n  "
		 "padding length = %hhu, next header = %hhu", &this->payload,
		 &padding, pad_length, this->next_header);
	return TRUE;
}

METHOD(esp_packet_t, decrypt, status_t,
	private_esp_packet_t *this, esp_context_t *esp_context)
{
	bio_reader_t *reader;
	u_int32_t spi, seq;
	chunk_t spi_seq, iv, icv, ciphertext;
	crypter_t *crypter;
	signer_t *signer;

	chunk_free(&this->payload);

	crypter = esp_context->get_crypter(esp_context);
	signer = esp_context->get_signer(esp_context);

	reader = bio_reader_create(this->packet_data);
	if (!reader->read_uint32(reader, &spi) ||
		!reader->read_uint32(reader, &seq) ||
		!reader->read_data(reader, crypter->get_iv_size(crypter), &iv) ||
		!reader->read_data_end(reader, signer->get_block_size(signer), &icv) ||
		reader->remaining(reader) % crypter->get_block_size(crypter))
	{
		DBG1(DBG_ESP, "ESP decryption failed: invalid length");
		return PARSE_ERROR;
	}
	ciphertext = reader->peek(reader);
	reader->destroy(reader);

	if (!esp_context->verify_seqno(esp_context, seq))
	{
		DBG1(DBG_ESP, "ESP sequence number verification failed:\n  "
			 "src %H, dst %H, SPI %.8x [seq %u]",
			 this->src, this->dst, spi, seq);
		return VERIFY_ERROR;
	}
	DBG3(DBG_ESP, "ESP decryption:\n  SPI %.8x [seq %u]\n  IV %B\n  "
		 "encrypted %B\n  ICV %B", spi, seq, &iv, &ciphertext, &icv);

	spi_seq = chunk_create(this->packet_data.ptr, 8);
	if (!signer->get_signature(signer, spi_seq, NULL) ||
		!signer->get_signature(signer, iv, NULL) ||
		!signer->verify_signature(signer, ciphertext, icv))
	{
		DBG1(DBG_ESP, "ICV verification failed!");
		return FAILED;
	}
	esp_context->set_authenticated_seqno(esp_context, seq);

	if (!crypter->decrypt(crypter, ciphertext, iv, &this->payload))
	{
		DBG1(DBG_ESP, "ESP decryption failed");
		return FAILED;
	}

	if (!remove_padding(this))
	{
		chunk_free(&this->payload);
		return PARSE_ERROR;
	}
	return SUCCESS;
}

/**
 * Generate the padding as specified in RFC4303
 */
static void generate_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		padding.ptr[i] = (u_int8_t)(i + 1);
	}
}

METHOD(esp_packet_t, encrypt, status_t,
	private_esp_packet_t *this, esp_context_t *esp_context, u_int32_t spi)
{
	chunk_t iv, icv, padding, ciphertext, auth_data;
	bio_writer_t *writer;
	u_int32_t next_seqno;
	size_t blocksize, plainlen;
	crypter_t *crypter;
	signer_t *signer;
	rng_t *rng;

	chunk_free(&this->packet_data);

	if (!esp_context->next_seqno(esp_context, &next_seqno))
	{
		DBG1(DBG_ESP, "ESP encapsulation failed: sequence numbers cycled");
		return FAILED;
	}

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_ESP, "ESP encryption failed: could not find RNG");
		return NOT_FOUND;
	}
	crypter = esp_context->get_crypter(esp_context);
	signer = esp_context->get_signer(esp_context);

	blocksize = crypter->get_block_size(crypter);
	iv.len = crypter->get_iv_size(crypter);
	icv.len = signer->get_block_size(signer);

	/* plaintext = payload, padding, pad_length, next_header */
	plainlen = this->payload.len + 2;
	padding.len = blocksize - (plainlen % blocksize);
	plainlen += padding.len;

	/* len = spi, seq, IV, plaintext, ICV */
	writer = bio_writer_create(2 * sizeof(u_int32_t) + iv.len + plainlen +
							   icv.len);
	writer->write_uint32(writer, ntohl(spi));
	writer->write_uint32(writer, next_seqno);

	iv = writer->skip(writer, iv.len);
	if (!rng->get_bytes(rng, iv.len, iv.ptr))
	{
		DBG1(DBG_ESP, "ESP encryption failed: could not generate IV");
		writer->destroy(writer);
		rng->destroy(rng);
		return FAILED;
	}
	rng->destroy(rng);

	/* plain-/ciphertext will start here */
	ciphertext = writer->get_buf(writer);
	ciphertext.ptr += ciphertext.len;
	ciphertext.len = plainlen;

	writer->write_data(writer, this->payload);

	padding = writer->skip(writer, padding.len);
	generate_padding(padding);

	writer->write_uint8(writer, padding.len);
	writer->write_uint8(writer, this->next_header);

	DBG3(DBG_ESP, "ESP before encryption:\n  payload = %B\n  padding = %B\n  "
		 "padding length = %hhu, next header = %hhu", &this->payload, &padding,
		 (u_int8_t)padding.len, this->next_header);

	/* encrypt the content inline */
	if (!crypter->encrypt(crypter, ciphertext, iv, NULL))
	{
		DBG1(DBG_ESP, "ESP encryption failed");
		writer->destroy(writer);
		return FAILED;
	}

	/* calculate signature */
	auth_data = writer->get_buf(writer);
	icv = writer->skip(writer, icv.len);
	if (!signer->get_signature(signer, auth_data, icv.ptr))
	{
		DBG1(DBG_ESP, "ESP encryption failed: signature generation failed");
		writer->destroy(writer);
		return FAILED;
	}

	DBG3(DBG_ESP, "ESP packet:\n  SPI %.8x [seq %u]\n  IV %B\n  "
		 "encrypted %B\n  ICV %B", ntohl(spi), next_seqno, &iv,
		 &ciphertext, &icv);

	this->packet_data = writer->extract_buf(writer);
	writer->destroy(writer);
	return SUCCESS;
}

METHOD(esp_packet_t, get_next_header, u_int8_t,
	private_esp_packet_t *this)
{
	return this->next_header;
}

METHOD(esp_packet_t, get_payload, chunk_t,
	private_esp_packet_t *this)
{
	return this->payload;
}

METHOD(esp_packet_t, get_packet_data, chunk_t,
	private_esp_packet_t *this)
{
	return this->packet_data;
}

METHOD(esp_packet_t, get_source, host_t*,
	private_esp_packet_t *this)
{
	return this->src;
}

METHOD(esp_packet_t, get_destination, host_t*,
	private_esp_packet_t *this)
{
	return this->dst;
}

METHOD(esp_packet_t, destroy, void,
	private_esp_packet_t *this)
{
	chunk_free(&this->payload);
	chunk_free(&this->packet_data);
	this->src->destroy(this->src);
	this->dst->destroy(this->dst);
	free(this);
}

static private_esp_packet_t *esp_packet_create_empty(host_t *src, host_t *dst)
{
	private_esp_packet_t *this;

	INIT(this,
		.public = {
			.get_source = _get_source,
			.get_destination = _get_destination,
			.get_packet_data = _get_packet_data,
			.get_payload = _get_payload,
			.get_next_header = _get_next_header,
			.parse_header = _parse_header,
			.decrypt = _decrypt,
			.encrypt = _encrypt,
			.destroy = _destroy,
		},
		.src = src,
		.dst = dst,
		.next_header = IPPROTO_NONE,
	);
	return this;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_packet(host_t *src, host_t *dst,
											chunk_t packet_data)
{
	private_esp_packet_t *this;

	this = esp_packet_create_empty(src, dst);
	this->packet_data = packet_data;

	return &this->public;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_payload(host_t *src, host_t *dst,
										chunk_t payload, u_int8_t next_header)
{
	private_esp_packet_t *this;

	this = esp_packet_create_empty(src, dst);
	this->next_header = next_header;
	this->payload = payload;

	return &this->public;
}

