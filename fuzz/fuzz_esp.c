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
#include <utils/debug.h>
#include <networking/host.h>
#include <networking/packet.h>
#include <ip_packet.h>
#include <esp_packet.h>

static host_t *src_v4;
static host_t *dst_v4;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_esp");

	/* Synthetic endpoints used only to wrap chunks into packet_t. */
	src_v4 = host_create_from_string("192.0.2.1", 4500);
	dst_v4 = host_create_from_string("192.0.2.2", 4500);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	ip_packet_t *ip;
	esp_packet_t *esp;
	packet_t *packet;
	chunk_t chunk;
	uint32_t spi;

	if (len < 20)
	{
		return 0;
	}

	chunk = chunk_create((u_char*)buf, len);

	/* Outer IP header parser. */
	ip = ip_packet_create(chunk_clone(chunk));
	if (ip)
	{
		ip->get_version(ip);
		ip->get_next_header(ip);
		ip->get_source(ip);
		ip->get_destination(ip);
		ip->get_encoding(ip);
		ip->get_payload(ip);
		ip->destroy(ip);
	}

	/* (2) ESP framing parser. */
	packet = packet_create_from_data(
		src_v4->clone(src_v4),
		dst_v4->clone(dst_v4),
		chunk_clone(chunk));
	esp = esp_packet_create_from_packet(packet);
	if (esp)
	{
		esp->parse_header(esp, &spi);
		esp->get_source(esp);
		esp->get_destination(esp);
		esp->destroy(esp);
	}
	return 0;
}
