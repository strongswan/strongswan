/*
 * Copyright (C) 2016 Andreas Steffen
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

#include "tpm_tss.h"

#include <library.h>
#include <utils/debug.h>
#include <utils/optionsfrom.h>

#include <syslog.h>
#include <getopt.h>
#include <errno.h>

/* default directory where AIK keys are stored */
#define AIK_DIR							IPSEC_CONFDIR "/pts/"

/* default name of AIK public key blob */
#define DEFAULT_FILENAME_AIKPUBKEY		AIK_DIR "aikPub.der"

/* logging */
static bool log_to_stderr = TRUE;
static bool log_to_syslog = TRUE;
static level_t default_loglevel = 1;

/* options read by optionsfrom */
options_t *options;

chunk_t aik_pubkey;
chunk_t aik_keyid;

/**
 * logging function for aikpub2
 */
static void aikpub2_dbg(debug_t group, level_t level, char *fmt, ...)
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
	dbg = aikpub2_dbg;

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
 * @brief exit aikgen
 *
 * @param status 0 = OK, -1 = general discomfort
 */
static void exit_aikpub2(err_t message, ...)
{
	int status = 0;

	free(aik_pubkey.ptr);
	free(aik_keyid.ptr);
	options->destroy(options);

	/* print any error message to stderr */
	if (message != NULL && *message != '\0')
	{
		va_list args;
		char m[8192];

		va_start(args, message);
		vsnprintf(m, sizeof(m), message, args);
		va_end(args);

		fprintf(stderr, "aikpub2 error: %s\n", m);
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
		"Usage: aikpub2  --handle <handle> --out <filename>\n"
		"               [--force] [--quiet] [--debug <level>]\n"
		"       aikpub2  --help\n"
		"\n"
		"Options:\n"
		" --handle (-H)     TSS 2.0 AIK object handle\n"
		" --out (-o)        AIK public key in PKCS #1 format\n"
		" --force (-f)      force to overwrite existing files\n"
		" --help (-h)       show usage and exit\n"
		"\n"
		"Debugging output:\n"
		" --debug (-l)      changes the log level (-1..4, default: 1)\n"
		" --quiet (-q)      do not write log output to stderr\n"
		);
	exit_aikpub2(message);
}


/**
 * @brief main of aikpub2 which extracts an Attestation Identity Key (AIK)
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char *argv[])
{
	/* external values */
	extern char * optarg;
	extern int optind;

	char *aik_out_filename = DEFAULT_FILENAME_AIKPUBKEY;
	uint32_t aik_handle = 0;
	bool force = FALSE;
	hasher_t *hasher;
	tpm_tss_t *tpm;

	atexit(library_deinit);
	if (!library_init(NULL, "aikpub2"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "aikpub2", argv[0]))
	{
		fprintf(stderr, "integrity check of aikpub2 failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}

	/* initialize global variables */
	options = options_create();

	for (;;)
	{
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "optionsfrom", required_argument, NULL, '+' },
			{ "handle", required_argument, NULL, 'H' },
			{ "in", required_argument, NULL, 'i' },
			{ "out", required_argument, NULL, 'o' },
			{ "force", no_argument, NULL, 'f' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "debug", required_argument, NULL, 'l' },
			{ 0,0,0,0 }
		};

		/* parse next option */
		int c = getopt_long(argc, argv, "h+:H:i:o:fql:", long_opts, NULL);

		switch (c)
		{
			case EOF:       /* end of flags */
				break;

			case 'h':       /* --help */
				usage(NULL);

			case '+':       /* --optionsfrom <filename> */
				if (!options->from(options, optarg, &argc, &argv, optind))
				{
					exit_aikpub2("optionsfrom failed");
				}
				continue;

			case 'H':       /* --handle <handle> */
				aik_handle = strtoll(optarg, NULL, 16);
				continue;

			case 'o':       /* --out <filename> */
				aik_out_filename = optarg;
				continue;

			case 'f':       /* --force */
				force = TRUE;
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

	init_log("aikpub2");

	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "aikpub2.load", PLUGINS)))
	{
		exit_aikpub2("plugin loading failed");
	}
	if (!aik_handle)
	{
		usage("--handle option is required");
	}

	/* try to find a TPM 2.0 */
	tpm = tpm_tss_probe(TPM_VERSION_2_0);
	if (!tpm)
	{
		exit_aikpub2("no TPM 2.0 found");	
	}

	/* get AIK public key from TPM */
	aik_pubkey = tpm->get_public(tpm, aik_handle);
	tpm->destroy(tpm);

	/* exit if AIK public key retrieval failed */
	if (aik_pubkey.len == 0)
	{
		exit_aikpub2("retrieval of AIK public key failed");
	}

	/* store AIK subjectPublicKeyInfo to file */
	if (!chunk_write(aik_pubkey, aik_out_filename, 0022, force))
	{
		exit_aikpub2("could not write AIK public key file '%s': %s",
					  aik_out_filename, strerror(errno));
	}
	DBG1(DBG_LIB, "AIK public key written to '%s' (%u bytes)",
				   aik_out_filename, aik_pubkey.len);

	/* AIK keyid derived from subjectPublicKeyInfo encoding */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		exit_aikpub2("SHA1 hash algorithm not supported");
	}
	if (!hasher->allocate_hash(hasher, aik_pubkey, &aik_keyid))
	{
		hasher->destroy(hasher);
		exit_aikpub2("computing SHA1 fingerprint failed");
	}
	hasher->destroy(hasher);

	DBG1(DBG_LIB, "AIK keyid: %#B", &aik_keyid);

	exit_aikpub2(NULL);
	return -1; /* should never be reached */
}
