/*
 * Copyright (C) 2020 Andreas Steffen
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <library.h>

static void usage(FILE *out, char *name)
{
	fprintf(out, "Convert NIST SIG KAT file into struct\n");
	fprintf(out, "%s [OPTIONS]\n\n", name);
	fprintf(out, "Options:\n");
	fprintf(out, "  -h, --help          print this help.\n");
	fprintf(out, "  -t, --type          signature type.\n");
	fprintf(out, "  -c, --count         number of structs (default 4).\n");
	fprintf(out, "  -i, --in=FILE       request file (default STDIN).\n");
	fprintf(out, "  -o, --out=FILE      response file (default STDOUT).\n");
	fprintf(out, "\n");
}

int main(int argc, char *argv[])
{
	FILE *in = stdin;
	FILE *out = stdout;
	char line[90000], *type = "", *pos, *eol, *param, *value;
	size_t param_len, value_len;
	int count = 4, n;

	library_init(NULL, "nist-kem-kat");
	atexit(library_deinit);

	while (true)
	{
		struct option long_opts[] = {
			{"help",	no_argument,		NULL,	'h' },
			{"type",	required_argument,	NULL,	't' },
			{"count",	required_argument,	NULL,	'c' },
			{"in",		required_argument,	NULL,	'i' },
			{"out",		required_argument,	NULL,	'o' },
			{0,0,0,0 },
		};
		switch (getopt_long(argc, argv, "h:t:c:i:o:", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout, argv[0]);
				return 0;
			case 't':
				type = optarg;
				continue;
			case 'c':
				count = atoi(optarg);
				continue;
			case 'i':
				in = fopen(optarg, "r");
				if (!in)
				{
					fprintf(stderr, "failed to open '%s': %s\n", optarg,
							strerror(errno));
					usage(stderr, argv[0]);
					return 1;
				}
				continue;
			case 'o':
				out = fopen(optarg, "w");
				if (!out)
				{
					fprintf(stderr, "failed to open '%s': %s\n", optarg,
							strerror(errno));
					usage(stderr, argv[0]);
					return 1;
				}
				continue;
			default:
				usage(stderr, argv[0]);
				return 1;
		}
		break;
	}

	while (fgets(line, sizeof(line), in))
	{
		pos = strchr(line, '=');
		if (!pos)
		{
			continue;
		}

		/*remove preceding whitespace from value */
		value = pos + 1;
		eol = strchr(value, '\n');
		if (!eol)
		{
			fprintf(stderr, "eol not found\n");
			break;
		}
		value_len = eol - value;
		while (value_len && *value == ' ')
		{
			value++;
			value_len--;
		}

		/* remove trailing whitespace from param */
		param = line;
		param_len = pos - line;
		while (param_len && *(--pos) == ' ')
		{
			param_len--;
		}
		param[param_len] = '\0';

		if (streq(param, "mlen") || streq(param, "smlen"))
		{
			continue;
		}

		if (streq(param, "count"))
		{
			if (count == 0)
			{
				break;
			}
			fprintf(out, "/** count = %.*s */\n", value_len, value);
			fprintf(out, "{\n");
			fprintf(out, "\t.type = %s,\n", type);
			count--;
		}
		else
		{
			fprintf(out, "\t.%s = chunk_from_chars(", param);
			n = 0;

			while (value_len > 1)
			{
				if (n > 0)
				{
					fprintf(out, ",");
					if (n % 100 == 0)
					{
						fprintf(out, " /* %d */\n", n);
					}
				}
				if (n % 10 == 0)
				{
					fprintf(out, "\n\t\t");
				}
				fprintf(out, "0x%.2s", value);
				value += 2;
				value_len -= 2;
				n++;
			}
			fprintf(out, "),\n");
			if (streq(param, "sm"))
			{
				fprintf(out, "},\n");
			}
		}
	}

	if (in != stdin)
	{
		fclose(in);
	}
	if (out != stdout)
	{
		fclose(out);
	}
	return 0;
}
