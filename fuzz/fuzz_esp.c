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
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	esp_packet_t *esp_packet, *esp_out;
	esp_context_t *esp_ctx;
	ip_packet_t *ip_packet, *payload_ip;
	packet_t *packet;
	host_t *src, *dst, *src2, *dst2, *src3, *dst3;
	uint32_t spi;
	chunk_t data, enc_key, int_key;

	/* Minimum ESP packet size */
	if (len < 8)
	{
		return 0;
	}

	/* Split input for different operations */
	size_t split = len / 2;
	if (split < 8) split = 8;

	/* Part 1: ESP packet parsing - packet_create_from_data takes ownership of hosts */
	src = host_create_from_string("192.0.2.1", 4500);
	dst = host_create_from_string("192.0.2.2", 4500);
	if (src && dst)
	{
		data = chunk_clone(chunk_create((u_char*)buf, split));
		packet = packet_create_from_data(src, dst, data);
		if (packet)
		{
			esp_packet = esp_packet_create_from_packet(packet);
			if (esp_packet)
			{
				if (esp_packet->parse_header(esp_packet, &spi))
				{
					esp_packet->get_source(esp_packet);
					esp_packet->get_destination(esp_packet);
					esp_packet->get_next_header(esp_packet);

					payload_ip = esp_packet->get_payload(esp_packet);
					DESTROY_IF(payload_ip);

					payload_ip = esp_packet->extract_payload(esp_packet);
					DESTROY_IF(payload_ip);
				}
				esp_packet->destroy(esp_packet);
			}
		}
	}

	/* Part 2: IP packet + ESP creation - create new hosts */
	if (len >= split + 20)
	{
		src2 = host_create_from_string("192.0.2.1", 4500);
		dst2 = host_create_from_string("192.0.2.2", 4500);
		if (src2 && dst2)
		{
			ip_packet = ip_packet_create(chunk_clone(chunk_create((u_char*)(buf + split), len - split)));
			if (ip_packet)
			{
				ip_packet->get_version(ip_packet);
				ip_packet->get_source(ip_packet);
				ip_packet->get_destination(ip_packet);
				ip_packet->get_next_header(ip_packet);
				ip_packet->get_payload(ip_packet);

				esp_out = esp_packet_create_from_payload(src2, dst2, ip_packet);
				if (esp_out)
				{
					esp_out->get_source(esp_out);
					esp_out->get_destination(esp_out);

					if (esp_out->parse_header(esp_out, &spi))
					{
						esp_out->get_next_header(esp_out);
					}

					esp_out->destroy(esp_out);
				}
				else
				{
					ip_packet->destroy(ip_packet);
					src2->destroy(src2);
					dst2->destroy(dst2);
				}
			}
			else
			{
				src2->destroy(src2);
				dst2->destroy(dst2);
			}
		}
	}

	/* Part 3: ESP context + decrypt operations - create new hosts */
	if (len >= 40)
	{
		src3 = host_create_from_string("192.0.2.1", 4500);
		dst3 = host_create_from_string("192.0.2.2", 4500);
		if (src3 && dst3)
		{
			enc_key = chunk_clone(chunk_create((u_char*)(buf + len - 32), 16));
			int_key = chunk_clone(chunk_create((u_char*)(buf + len - 16), 16));

			esp_ctx = esp_context_create(12, enc_key, 2, int_key, TRUE);
			if (esp_ctx)
			{
				esp_ctx->get_seqno(esp_ctx);
				esp_ctx->verify_seqno(esp_ctx, 1);

				data = chunk_clone(chunk_create((u_char*)buf, len > 32 ? len - 32 : len));
				packet = packet_create_from_data(src3, dst3, data);
				if (packet)
				{
					esp_packet = esp_packet_create_from_packet(packet);
					if (esp_packet && esp_packet->parse_header(esp_packet, &spi))
					{
						esp_packet->decrypt(esp_packet, esp_ctx);
					}
					DESTROY_IF(esp_packet);
				}

				esp_ctx->destroy(esp_ctx);
			}
			else
			{
				src3->destroy(src3);
				dst3->destroy(dst3);
			}

			chunk_free(&enc_key);
			chunk_free(&int_key);
		}
	}

	return 0;
}
