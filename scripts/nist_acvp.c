/*
 * Copyright (C) 2024 Andreas Steffen
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
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <library.h>

static void usage(FILE *out, char *name)
{
	fprintf(out, "Convert NIST ACVP JSON entries into struct\n");
	fprintf(out, "%s [OPTIONS]\n\n", name);
	fprintf(out, "Options:\n");
	fprintf(out, "  -h, --help          print this help.\n");
	fprintf(out, "  -i, --in=FILE       request file (default STDIN).\n");
	fprintf(out, "  -o, --out=FILE      response file (default STDOUT).\n");
	fprintf(out, "\n");
}

int main(int argc, char *argv[])
{
	FILE *in = stdin;
	FILE *out = stdout;
	char line[90000], *pos, *eol, *param, *value;
	size_t param_len, value_len;
	int n = 0;

	library_init(NULL, "nist-kem-kat");
	atexit(library_deinit);

	while (true)
	{
		struct option long_opts[] = {
			{"help",	no_argument,		NULL,	'h' },
			{"in",		required_argument,	NULL,	'i' },
			{"out",		required_argument,	NULL,	'o' },
			{0,0,0,0 },
		};
		switch (getopt_long(argc, argv, "h:m:c:i:o:", long_opts, NULL))
		{
			case EOF:
				break;
			case 'h':
				usage(stdout, argv[0]);
				return 0;
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
		pos = strchr(line, ':');
		if (!pos)
		{
			continue;
		}
		value = pos + 1;

		/* determine end of line */
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

		/* remove optional comma trailing the value */
		if (value_len && value[value_len-1] == ',')
		{
			value_len--;
		}

		if (value_len < 2 || *value != '"' || value[value_len-1] != '"')
		{
			fprintf(stderr, "no double quotes around value found\n");
			break;
		}
		value++;
		value_len -= 2;

		param = line;
		param_len = pos - line;

		/*remove preceding whitespace from param */
		while (param_len && *param == ' ')
		{
			param++;
			param_len--;
		}

		/* remove double quotes from param */
		if (*param != '"' || param[param_len - 1] != '"')
		{
			fprintf(stderr, "no double quotes around found\n");
			break;
		}
		param++;
		param_len -= 2;
		param[param_len] = '\0';

		fprintf(out, "%s:\n", param);
  		fprintf(out, "\t  chunk_from_chars(");

  		n = 0;
		while (value_len > 1)
		{
			if (n > 0)
			{
				fprintf(out, ",");
				if (n % 80 == 0)
				{
					fprintf(out, " /* %4d */", n);
				}
			}
			if (n % 16 == 0)
			{
				fprintf(out, "\n\t\t");
			}
			fprintf(out, "0x%c%c", tolower(value[0]), tolower(value[1]));
			value += 2;
			value_len -= 2;
			n++;
		}
		fprintf(out, "),/* %4d */\n", n);
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
