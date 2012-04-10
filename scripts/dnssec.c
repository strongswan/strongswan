/*
 * Copyright (C) 2011-2012 Reto Guadagnini
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

int main(int argc, char *argv[])
{
	resolver_t *resolver;
	resolver_response_t *response;
	enumerator_t *enumerator;
	rr_set_t *rrset;
	rr_t *rr;
	chunk_t chunk;

	library_init(NULL);
	atexit(library_deinit);
	if (!lib->plugins->load(lib->plugins, NULL, PLUGINS))
	{
		return 1;
	}
	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <name>\n", argv[0]);
		return 1;
	}

	resolver = lib->resolver->create(lib->resolver);
	if (!resolver)
	{
		printf("failed to create a resolver!\n");
		return 1;
	}

	response = resolver->query(resolver, argv[1], RR_CLASS_IN, RR_TYPE_A);
	if (!response)
	{
		printf("no response received!\n");
		resolver->destroy(resolver);
		return 1;
	}

	printf("DNS response:\n");
	if (!response->has_data(response) || !response->query_name_exist(response))
	{
		if (!response->has_data(response))
		{
			printf("  no data in the response\n");
		}
		if (!response->query_name_exist(response))
		{
			printf("  query name does not exist\n");
		}
		response->destroy(response);
		resolver->destroy(resolver);
		return 1;
	}

	printf("  RRs in the response:\n");
	rrset = response->get_rr_set(response);
	if (!rrset)
	{
		printf("    response contains no RRset!\n");
		response->destroy(response);
		resolver->destroy(resolver);
		return 1;
	}

	enumerator = rrset->create_rr_enumerator(rrset);
	while (enumerator->enumerate(enumerator, &rr))
	{
		printf("    name: ");
		printf(rr->get_name(rr));
		printf("\n");
	}

	enumerator = rrset->create_rrsig_enumerator(rrset);
	if (enumerator)
	{
		printf("  RRSIGs for the RRset:\n");
		while (enumerator->enumerate(enumerator, &rr))
		{
			printf("    name: ");
			printf(rr->get_name(rr));
			printf("\n    RDATA: ");
			chunk = rr->get_rdata(rr);
			chunk = chunk_to_hex(chunk, NULL, TRUE);
			printf(chunk.ptr);
			printf("\n");
		}
	}

	printf("  security status of the response: ");
	switch (response->get_security_state(response))
	{
		case SECURE:
			printf("SECURE\n\n");
			break;
		case INSECURE:
			printf("INSECURE\n\n");
			break;
		case BOGUS:
			printf("BOGUS\n\n");
			break;
		case INDETERMINATE:
			printf("INDETERMINATE\n\n");
			break;
	}
	response->destroy(response);
	resolver->destroy(resolver);
	return 0;
}
