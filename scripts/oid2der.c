/*
 * Copyright (C) 2010 Martin Willi
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

#include <stdio.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>

/**
 * Print the path for the given OID
 */
static void print_path(FILE *out, int oid)
{
	if (oid == OID_UNKNOWN)
	{
		fprintf(out, "<unknown OID>:\n");
	}
	else
	{
		int level = oid_names[oid].level, path[level+1];

		path[level] = oid;
		while (level > 0)
		{
			if (oid_names[oid].level < level)
			{
				path[--level] = oid;
			}
			oid--;
		}
		for (level = 0; level < countof(path); level++)
		{
			const char *name = oid_names[path[level]].name;

			fprintf(out, "%s%s", level > 0 ? "›" : "",
					name[0] ? name : "…");
		}
		fprintf(out, ":\n", oid_names[oid].name);
	}
}

/**
 * convert string OID to DER encoding
 */
int main(int argc, char *argv[])
{
	int i, nr = 0, known;
	chunk_t oid;
	char *decoded;
	bool decode = FALSE;

	if (streq(argv[1], "-d"))
	{
		decode = TRUE;
		nr++;
	}

	while (argc > ++nr)
	{
		if (decode)
		{
			oid = chunk_from_hex(chunk_from_str(argv[nr]), NULL);
		}
		else
		{
			oid = asn1_oid_from_string(argv[nr]);
		}

		if (oid.len)
		{
			known = asn1_known_oid(oid);
			print_path(stderr, known);
		}
		else
		{
			return 1;
		}

		if (decode)
		{
			decoded = asn1_oid_to_string(oid);
			if (decoded)
			{
				printf("%s\n", decoded);
				free(decoded);
			}
			else
			{
				fprintf(stderr, "<unable to encode OID>\n");
			}
		}
		else
		{
			for (i = 0; i < oid.len; i++)
			{
				printf("0x%02x,", oid.ptr[i]);
			}
			printf("\n");
		}
		free(oid.ptr);
	}
	return 0;
}
