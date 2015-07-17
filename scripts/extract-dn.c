/*
 * Copyright (C) 2015 Tobias Brunner
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

#include <library.h>

static void usage(FILE *out, char *name)
{
	fprintf(out, "Extract the ASN.1 subject DN from a certificate\n\n");
	fprintf(out, "%s [OPTIONS]\n\n", name);
	fprintf(out, "Options:\n");
	fprintf(out, "  -h, --help          print this help.\n");
	fprintf(out, "  -i, --in=FILE       certificate file (default STDIN).\n");
	fprintf(out, "  -f, --format=FORMAT output format (config, hex, base64, binary).\n");
	fprintf(out, "\n");
}

/**
 * Extract the binary ASN.1 subject DN from a certificate
 */
int main(int argc, char *argv[])
{
	identification_t *id;
	certificate_t *cert;
	chunk_t chunk;
	enum {
		FORMAT_CONFIG,
		FORMAT_HEX,
		FORMAT_BASE64,
		FORMAT_BINARY,
	} format = FORMAT_CONFIG;
	int fd = 0;
	char *fmt;

	library_init(NULL, "extract-dn");
	atexit(library_deinit);

	while (true)
	{
		struct option long_opts[] = {
			{"help",		no_argument,		NULL,	'h' },
			{"in",			required_argument,	NULL,	'i' },
			{"format",		required_argument,	NULL,	'f' },
			{0,0,0,0 },
		};
		switch (getopt_long(argc, argv, "hi:f:", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout, argv[0]);
				return 0;
			case 'i':
				fd = open(optarg, O_RDONLY);
				if (fd == -1)
				{
					fprintf(stderr, "failed to open '%s': %s\n", optarg,
							strerror(errno));
					usage(stderr, argv[0]);
					return 1;
				}
				continue;
			case 'f':
				if (streq(optarg, "hex"))
				{
					format = FORMAT_HEX;
				}
				else if (streq(optarg, "base64"))
				{
					format = FORMAT_BASE64;
				}
				else if (streq(optarg, "bin"))
				{
					format = FORMAT_BINARY;
				}
				continue;
			default:
				usage(stderr, argv[0]);
				return 1;
		}
		break;
	}
	/* TODO: maybe make plugins configurable */
	lib->plugins->load(lib->plugins, PLUGINS);

	if (!chunk_from_fd(fd, &chunk))
	{
		fprintf(stderr, "reading input failed: %s\n", strerror(errno));
		return 1;
	}
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_BLOB, chunk, BUILD_END);
	chunk_free(&chunk);
	if (fd != 0)
	{
		close(fd);
	}

	if (!cert)
	{
		fprintf(stderr, "failed to read certificate\n");
		return 1;
	}
	id = cert->get_subject(cert);
	if (!id)
	{
		fprintf(stderr, "failed to get certificate's subject DN\n");
		cert->destroy(cert);
		return 1;
	}
	fmt = "%.*s\n";
	switch (format)
	{
		case FORMAT_CONFIG:
			fmt = "\"asn1dn:#%.*s\"\n";
			/* fall-through */
		case FORMAT_HEX:
			chunk = chunk_to_hex(id->get_encoding(id), NULL, FALSE);
			printf(fmt, (int)chunk.len, chunk.ptr);
			chunk_free(&chunk);
			break;
		case FORMAT_BASE64:
			chunk = chunk_to_base64(id->get_encoding(id), NULL);
			printf(fmt, (int)chunk.len, chunk.ptr);
			chunk_free(&chunk);
			break;
		case FORMAT_BINARY:
			chunk = id->get_encoding(id);
			if (fwrite(chunk.ptr, chunk.len, 1, stdout) != 1)
			{
				fprintf(stderr, "writing subject DN failed\n");
			}
			break;
	}
	cert->destroy(cert);
	return 0;
}
