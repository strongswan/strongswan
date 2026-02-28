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
	plugin_loader_add_plugindirs(PLUGINDIR, PLUGINS);

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
	ip_packet_t *payload_ip;
	host_t *src, *dst;
	uint32_t spi;
	chunk_t enc_key, int_key, packet_data;

	if (len < 32)
	{
		return 0;
	}

	/* Extract encryption and integrity keys from fuzzer input (no clone needed) */
	enc_key = chunk_create((u_char*)buf, 16);
	int_key = chunk_create((u_char*)(buf + 16), 16);

	/* Create ESP packet from remaining fuzzer data (inbound path) */
	packet_data = chunk_clone(chunk_create((u_char*)(buf + 32), len - 32));
	src = host_create_from_string("192.0.2.1", 4500);
	dst = host_create_from_string("192.0.2.2", 4500);
	esp_packet = esp_packet_create_from_packet(packet_create_from_data(src, dst, packet_data));
	if (!esp_packet)
	{
		src->destroy(src);
		dst->destroy(dst);
		return 0;
	}

	/* Parse ESP header */
	if (esp_packet->parse_header(esp_packet, &spi))
	{
		esp_packet->get_next_header(esp_packet);
	}

	/* Create outbound and inbound ESP contexts */
	esp_ctx_out = esp_context_create(ENCR_AES_CBC, enc_key, AUTH_HMAC_SHA2_256_128, int_key, FALSE);
	esp_ctx_in = esp_context_create(ENCR_AES_CBC, enc_key, AUTH_HMAC_SHA2_256_128, int_key, TRUE);

	if (esp_ctx_out && esp_ctx_in)
	{
		/* Try to decrypt with inbound context (fuzzer provides encrypted ESP packets) */
		if (esp_packet->decrypt(esp_packet, esp_ctx_in) == SUCCESS)
		{
			payload_ip = esp_packet->get_payload(esp_packet);
			DESTROY_IF(payload_ip);

			payload_ip = esp_packet->extract_payload(esp_packet);
			DESTROY_IF(payload_ip);
		}
	}

	/* Cleanup */
	DESTROY_IF(esp_ctx_out);
	DESTROY_IF(esp_ctx_in);
	esp_packet->destroy(esp_packet);

	return 0;
}

