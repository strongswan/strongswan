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
	plugin_loader_t *loader;

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_esp");
	libipsec_init();

	loader = lib->plugins;
	if (!loader->load(loader, "sha1") ||
		!loader->load(loader, "aes") ||
		!loader->load(loader, "hmac") ||
		!loader->load(loader, "nonce") ||
		!loader->load(loader, "random"))
	{
		return 1;
	}

	return 0;
}

static void create_host_pair(host_t **src, host_t **dst)
{
	*src = host_create_from_string("192.0.2.1", 4500);
	*dst = host_create_from_string("192.0.2.2", 4500);
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	esp_packet_t *esp_packet;
	esp_context_t *esp_ctx;
	ip_packet_t *ip_packet, *payload_ip;
	host_t *src, *dst;
	uint32_t spi;
	chunk_t enc_key, int_key;

	if (len < 48)
	{
		return 0;
	}

	/* Extract encryption and integrity keys from fuzzer input */
	enc_key = chunk_clone(chunk_create((u_char*)buf, 16));
	int_key = chunk_clone(chunk_create((u_char*)(buf + 16), 16));

	/* Create IP packet from remaining fuzzer data */
	ip_packet = ip_packet_create(chunk_clone(chunk_create((u_char*)(buf + 32), len - 32)));
	if (!ip_packet)
	{
		chunk_free(&enc_key);
		chunk_free(&int_key);
		return 0;
	}

	/* Test IP packet operations */
	ip_packet->get_version(ip_packet);
	ip_packet->get_source(ip_packet);
	ip_packet->get_destination(ip_packet);
	ip_packet->get_next_header(ip_packet);

	/* Create host pair for ESP packet */
	create_host_pair(&src, &dst);
	if (!src || !dst)
	{
		ip_packet->destroy(ip_packet);
		chunk_free(&enc_key);
		chunk_free(&int_key);
		DESTROY_IF(src);
		DESTROY_IF(dst);
		return 0;
	}

	/* Create ESP packet from IP payload */
	esp_packet = esp_packet_create_from_payload(src, dst, ip_packet);
	if (!esp_packet)
	{
		ip_packet->destroy(ip_packet);
		src->destroy(src);
		dst->destroy(dst);
		chunk_free(&enc_key);
		chunk_free(&int_key);
		return 0;
	}

	/* Test ESP packet operations before encryption */
	esp_packet->get_source(esp_packet);
	esp_packet->get_destination(esp_packet);

	if (esp_packet->parse_header(esp_packet, &spi))
	{
		esp_packet->get_next_header(esp_packet);
	}

	/* Create ESP context and perform encryption/decryption */
	esp_ctx = esp_context_create(12, enc_key, 2, int_key, FALSE);
	if (esp_ctx)
	{
		/* Encrypt the ESP packet */
		if (esp_packet->encrypt(esp_packet, esp_ctx, 0x12345678) == SUCCESS)
		{
			/* Test operations on encrypted packet */
			esp_packet->get_source(esp_packet);
			esp_packet->get_destination(esp_packet);

			/* Decrypt and extract payload */
			if (esp_packet->decrypt(esp_packet, esp_ctx) == SUCCESS)
			{
				payload_ip = esp_packet->get_payload(esp_packet);
				DESTROY_IF(payload_ip);

				payload_ip = esp_packet->extract_payload(esp_packet);
				DESTROY_IF(payload_ip);
			}
		}
		esp_ctx->destroy(esp_ctx);
	}

	/* Cleanup */
	esp_packet->destroy(esp_packet);
	chunk_free(&enc_key);
	chunk_free(&int_key);

	return 0;
}

