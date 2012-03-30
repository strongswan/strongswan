/*
 * Copyright (C) 2012 Tobias Brunner
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

#include <stdio.h>

#include <library.h>
#include <utils/host.h>
#include <utils/enumerator.h>
#include <selectors/traffic_selector.h>

#define swap(a, b) ({ typeof(a) _tmp = a; a = b; b = _tmp; })

/**
 * Split an IP address range into multiple distinct subnets.
 */
int main(int argc, char *argv[])
{
	enumerator_t *enumerator;
	host_t *from = NULL, *to = NULL, *net;
	chunk_t from_addr, to_addr;
	traffic_selector_t *ts;
	ts_type_t type;
	u_int8_t mask;
	char *token;
	int family;

	library_init(NULL);
	atexit(library_deinit);

	if (argc != 2)
	{
		printf("Usage: %s <from>-<to>\n", argv[0]);
		return -1;
	}

	enumerator = enumerator_create_token(argv[1], "-", " ");
	while (enumerator->enumerate(enumerator, &token))
	{
		host_t **host;
		host = !from ? &from : &to;
		*host = host_create_from_string(token, 0);
		if (*host == NULL)
		{
			printf("Unable to parse IP address: %s\n", token);
			enumerator->destroy(enumerator);
			DESTROY_IF(from);
			return -2;
		}
	}
	enumerator->destroy(enumerator);

	if (!to)
	{
		to = from->clone(from);
	}

	if (from->get_family(from) != to->get_family(to))
	{
		printf("Address family does not match!");
		from->destroy(from);
		to->destroy(to);
		return -3;
	}

	family = from->get_family(from);
	from_addr = from->get_address(from);
	to_addr = to->get_address(to);

	if (chunk_compare(from_addr, to_addr) > 0)
	{
		swap(from_addr, to_addr);
		swap(from, to);
	}

	printf("Splitting range %H-%H...\n", from, to);

	type = (family == AF_INET) ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE;
	ts = traffic_selector_create_from_bytes(0, type, from_addr, 0, to_addr, 0);

	ts->to_subnet(ts, &net, &mask);
	printf("Simplfied subnet:\n %H/%d\n", net, mask);
	net->destroy(net);

	printf("Subnets:\n");
	enumerator = ts->create_subnet_enumerator(ts);
	while (enumerator->enumerate(enumerator, &net, &mask))
	{
		printf(" %H/%d\n", net, mask);
	}
	enumerator->destroy(enumerator);

	from->destroy(from);
	to->destroy(to);
	ts->destroy(ts);
	return 0;
}

