/*
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include <tpm_tss.h>

#include <library.h>
#include <crypto/hashers/hasher.h>
#include <utils/lexparser.h>
#include <utils/debug.h>

#include <syslog.h>
#include <getopt.h>
#include <errno.h>


/* logging */
static bool log_to_stderr = TRUE;
static bool log_to_syslog = TRUE;
static level_t default_loglevel = 1;

/* global variables */
tpm_tss_t *tpm;

/**
 * logging function for tpm_seal
 */
static void tpm_seal_dbg(debug_t group, level_t level, char *fmt, ...)
{
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (level <= default_loglevel)
	{
		if (log_to_stderr)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			va_end(args);
			fprintf(stderr, "\n");
		}
		if (log_to_syslog)
		{
			/* write in memory buffer first */
			va_start(args, fmt);
			vsnprintf(buffer, sizeof(buffer), fmt, args);
			va_end(args);

			/* do a syslog with every line */
			while (current)
			{
				next = strchr(current, '\n');
				if (next)
				{
					*(next++) = '\0';
				}
				syslog(LOG_INFO, "%s\n", current);
				current = next;
			}
		}
	}
}

/**
 * Initialize logging to stderr/syslog
 */
static void init_log(const char *program)
{
	dbg = tpm_seal_dbg;

	if (log_to_stderr)
	{
		setbuf(stderr, NULL);
	}
	if (log_to_syslog)
	{
		openlog(program, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_AUTHPRIV);
	}
}

/**
 * @brief exit tpm_seal
 *
 * @param status 0 = OK, -1 = general discomfort
 */
static void exit_tpm_seal(err_t message, ...)
{
	int status = 0;

	DESTROY_IF(tpm);

	/* print any error message to stderr */
	if (message != NULL && *message != '\0')
	{
		va_list args;
		char m[8192];

		va_start(args, message);
		vsnprintf(m, sizeof(m), message, args);
		va_end(args);

		fprintf(stderr, "tpm_seal error: %s\n", m);
		status = -1;
	}
	library_deinit();
	exit(status);
}

/**
 * @brief prints the usage of the program to the stderr output
 *
 * If message is set, program is exited with 1 (error)
 * @param message message in case of an error
 */
static void usage(const char *message)
{
	fprintf(stderr,
		"Usage: tpm_seal [--alg <name>] --pcrs <list> --in <file>\n"
		"                [--out <file>] [--quiet] [--debug <level>]\n"
		"       tpm_seal  --help\n"
		"\n"
		"Options:\n"
		" --alg (-a)     hash algorithm (sha1|sha256)\n"
		" --pcrs (-p)    list of platform configuration registers (0..23)\n"
		" --in (-i)      binary input file with digest to be extended\n"
		" --out (-o)     binary output file with updated PCR value\n"
		" --help (-h)    show usage and exit\n"
		"\n"
		"Debugging output:\n"
		" --debug (-l)   changes the log level (-1..4, default: 1)\n"
		" --quiet (-q)   do not write log output to stderr\n"
		);
	exit_tpm_seal(message);
}

static uint32_t parse_pcrs(char *pcrs)
{
	chunk_t pcr_list, pcr_range, pcr_start;
	uint32_t pcr, pcr_stop, pcr_sel;

	pcr_list = chunk_from_str(pcrs);
	pcr_sel = 0x00000000;

	while (pcr_list.len > 0)
	{
		if (!extract_token(&pcr_range, ',', &pcr_list))
		{
			pcr_range = pcr_list;
			pcr_list = chunk_empty;
		}
		if (extract_token(&pcr_start, '-', &pcr_range))
		{
			pcr       = atoi(pcr_start.ptr);
			pcr_stop  = atoi(pcr_range.ptr);
		}
		else
		{
			pcr       = atoi(pcr_range.ptr);
			pcr_stop  = pcr;
		}

		while (pcr <= pcr_stop)
		{
			pcr_sel |= (1 << pcr++);
		}
	}
	return pcr_sel;
}

/**
 * @brief main of tpm_seal which extends digest into a PCR
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char *argv[])
{
	hash_algorithm_t alg = HASH_SHA1;
	char *infile = NULL, *outfile = NULL, *pcrs = "";
	uint32_t pcr_sel;

	atexit(library_deinit);
	if (!library_init(NULL, "tpm_seal"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "tpm_seal", argv[0]))
	{
		fprintf(stderr, "integrity check of tpm_seal failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}

	for (;;)
	{
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "alg", required_argument, NULL, 'a' },
			{ "pcrs", required_argument, NULL, 'p' },
			{ "in", required_argument, NULL, 'i' },
			{ "out", required_argument, NULL, 'o' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "debug", required_argument, NULL, 'l' },
			{ 0,0,0,0 }
		};

		/* parse next option */
		int c = getopt_long(argc, argv, "ha:p:i:o:ql:", long_opts, NULL);

		switch (c)
		{
			case EOF:       /* end of flags */
				break;

			case 'h':       /* --help */
				usage(NULL);

			case 'a':       /* --alg <name> */
				if (!enum_from_name(hash_algorithm_short_names, optarg, &alg))
				{
					usage("unsupported hash algorithm");
				}
				continue;
			case 'p':       /* --pcrs <list> */
				pcrs = optarg;
				continue;

			case 'i':       /* --in <file> */
				infile = optarg;
				continue;

			case 'o':       /* --out <file> */
				outfile = optarg;
				continue;

			case 'q':       /* --quiet */
				log_to_stderr = FALSE;
				continue;

			case 'l':		/* --debug <level> */
				default_loglevel = atoi(optarg);
				continue;

			default:
				usage("unknown option");
		}
		/* break from loop */
		break;
	}

	/* parse PCR selection */
	pcr_sel = parse_pcrs(pcrs);
	if (pcr_sel == 0)
	{
		usage("no PCRs selected");
	}

	init_log("tpm_seal");

	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "tpm_seal.load", "tpm sha2")))
	{
		exit_tpm_seal("plugin loading failed");
	}

	/* try to find a TPM */
	tpm = tpm_tss_probe(TPM_VERSION_2_0);
	if (!tpm)
	{
		exit_tpm_seal("no TPM found");
	}

	/* sealing operation */
	if (!tpm->seal(tpm, alg, pcr_sel))
	{
		exit_tpm_seal("sealing failed");
	}

	exit_tpm_seal(NULL);
	return -1; /* should never be reached */
}
