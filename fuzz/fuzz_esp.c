/*
 * Copyright (C) 2026 Arthur SC Chan
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

#include <library.h>
#include <ipsec.h>
#include <esp_packet.h>
#include <esp_context.h>
#include <ip_packet.h>
#include <networking/packet.h>
#include <networking/host.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_esp");
	libipsec_init();

	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	esp_packet_t *esp_packet;
	esp_context_t *esp_ctx_out, *esp_ctx_in;
	ip_packet_t *plaintext_ip;
	host_t *src, *dst;
	uint32_t spi = htonl(0x12345678);
	chunk_t fixed_enc_key, fixed_int_key;

	/* Fixed encryption key (not from fuzzer input) */
	fixed_enc_key = chunk_from_chars(
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F);

	/* Fixed integrity key (not from fuzzer input) */
	fixed_int_key = chunk_from_chars(
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F);

	/* Create IP packet from fuzzer input (plaintext to encrypt) */
	plaintext_ip = ip_packet_create(chunk_clone(chunk_create((u_char*)buf, len)));
	if (!plaintext_ip)
	{
		return 0;
	}

	/* Create hosts for ESP packet */
	src = host_create_from_string("192.0.2.1", 4500);
	dst = host_create_from_string("192.0.2.2", 4500);

	/* Create ESP packet from plaintext payload (takes ownership of src/dst) */
	esp_packet = esp_packet_create_from_payload(src, dst, plaintext_ip);
	if (!esp_packet)
	{
		src->destroy(src);
		dst->destroy(dst);
		return 0;
	}

	/* Create outbound ESP context */
	esp_ctx_out = esp_context_create(ENCR_AES_CBC, fixed_enc_key,
									  AUTH_HMAC_SHA2_256_128, fixed_int_key, FALSE);
	if (!esp_ctx_out)
	{
		esp_packet->destroy(esp_packet);
		return 0;
	}

	/* Encrypt to create valid ESP packet */
	if (esp_packet->encrypt(esp_packet, esp_ctx_out, spi) == SUCCESS)
	{
		/* Create inbound ESP context */
		esp_ctx_in = esp_context_create(ENCR_AES_CBC, fixed_enc_key,
										 AUTH_HMAC_SHA2_256_128, fixed_int_key, TRUE);
		if (esp_ctx_in)
		{
			/* Decrypt and parse */
			if (esp_packet->decrypt(esp_packet, esp_ctx_in) == SUCCESS)
			{
				/* Access next header after decryption */
				esp_packet->get_next_header(esp_packet);
			}

			esp_ctx_in->destroy(esp_ctx_in);
		}
	}

	/* Cleanup */
	esp_ctx_out->destroy(esp_ctx_out);
	esp_packet->destroy(esp_packet);

	return 0;
}

