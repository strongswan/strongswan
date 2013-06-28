/**
 * @file openac.c
 *
 * @brief Generation of X.509 attribute certificates.
 *
 */

/*
 * Copyright (C) 2002  Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2004,2007  Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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
#include <syslog.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>

#include <library.h>
#include <utils/debug.h>
#include <asn1/asn1.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/ac.h>
#include <credentials/keys/private_key.h>
#include <credentials/sets/mem_cred.h>
#include <utils/optionsfrom.h>

#define OPENAC_PATH			IPSEC_CONFDIR "/openac"
#define OPENAC_SERIAL		IPSEC_CONFDIR "/openac/serial"

#define DEFAULT_VALIDITY	24*3600		/* seconds */

/**
 * @brief prints the usage of the program to the stderr
 */
static void usage(const char *message)
{
	if (message != NULL && *message != '\0')
	{
		fprintf(stderr, "%s\n", message);
	}
	fprintf(stderr, "Usage: openac"
		" [--help]"
		" [--version]"
		" [--optionsfrom <filename>]"
		" [--quiet]"
		" \\\n\t"
		"      [--debug <level 0..4>]"
		" \\\n\t"
		"      [--days <days>]"
		" [--hours <hours>]"
		" \\\n\t"
		"      [--startdate <YYYYMMDDHHMMSSZ>]"
		" [--enddate <YYYYMMDDHHMMSSZ>]"
		" \\\n\t"
		"      --cert <certfile>"
		" --key <keyfile>"
		" [--password <password>]"
		" \\\n\t"
		"      --usercert <certfile>"
		" --groups <attr1,attr2,..>"
		" --out <filename>"
		"\n"
	);
}

/**
 * read the last serial number from file
 */
static chunk_t read_serial(void)
{
	chunk_t hex, serial = chunk_empty;
	char one[] = {0x01};
	FILE *fd;

	fd = fopen(OPENAC_SERIAL, "r");
	if (fd)
	{
		hex = chunk_alloca(64);
		hex.len = fread(hex.ptr, 1, hex.len, fd);
		if (hex.len)
		{
			/* remove any terminating newline character */
			if (hex.ptr[hex.len-1] == '\n')
			{
				hex.len--;
			}
			serial = chunk_alloca((hex.len / 2) + (hex.len % 2));
			serial = chunk_from_hex(hex, serial.ptr);
		}
		fclose(fd);
	}
	else
	{
		DBG1(DBG_LIB, "  file '%s' does not exist yet - serial number "
			 "set to 01", OPENAC_SERIAL);
	}
	if (!serial.len)
	{
		return chunk_clone(chunk_create(one, 1));
	}
	if (chunk_increment(serial))
	{	/* overflow, prepend 0x01 */
		return chunk_cat("cc", chunk_create(one, 1), serial);
	}
	return chunk_clone(serial);
}

/**
 * write back the last serial number to file
 */
static void write_serial(chunk_t serial)
{
	FILE *fd = fopen(OPENAC_SERIAL, "w");

	if (fd)
	{
		chunk_t hex_serial;

		DBG1(DBG_LIB, "  serial number is %#B", &serial);
		hex_serial = chunk_to_hex(serial, NULL, FALSE);
		fprintf(fd, "%.*s\n", (int)hex_serial.len, hex_serial.ptr);
		fclose(fd);
		free(hex_serial.ptr);
	}
	else
	{
		DBG1(DBG_LIB, "  could not open file '%s' for writing", OPENAC_SERIAL);
	}
}

/**
 * global variables accessible by both main() and build.c
 */

static int debug_level = 1;
static bool stderr_quiet = FALSE;

/**
 * openac dbg function
 */
static void openac_dbg(debug_t group, level_t level, char *fmt, ...)
{
	int priority = LOG_INFO;
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (level <= debug_level)
	{
		if (!stderr_quiet)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
			va_end(args);
		}

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
			syslog(priority, "%s\n", current);
			current = next;
		}
	}
}

/**
 * @brief openac main program
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char **argv)
{
	certificate_t *attr_cert   = NULL;
	certificate_t *userCert   = NULL;
	certificate_t *signerCert = NULL;
	private_key_t *signerKey  = NULL;

	time_t notBefore = UNDEFINED_TIME;
	time_t notAfter  = UNDEFINED_TIME;
	time_t validity = 0;

	char *keyfile = NULL;
	char *certfile = NULL;
	char *usercertfile = NULL;
	char *outfile = NULL;
	char *groups = "";
	char buf[BUF_LEN];

	chunk_t passphrase = { buf, 0 };
	chunk_t serial = chunk_empty;
	chunk_t attr_chunk = chunk_empty;

	int status = 1;

	/* enable openac debugging hook */
	dbg = openac_dbg;

	passphrase.ptr[0] = '\0';

	openlog("openac", 0, LOG_AUTHPRIV);

	/* initialize library */
	atexit(library_deinit);
	if (!library_init(NULL))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "openac", argv[0]))
	{
		fprintf(stderr, "integrity check of openac failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "openac.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	/* initialize optionsfrom */
	options_t *options = options_create();

	/* handle arguments */
	for (;;)
	{
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "optionsfrom", required_argument, NULL, '+' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "cert", required_argument, NULL, 'c' },
			{ "key", required_argument, NULL, 'k' },
			{ "password", required_argument, NULL, 'p' },
			{ "usercert", required_argument, NULL, 'u' },
			{ "groups", required_argument, NULL, 'g' },
			{ "days", required_argument, NULL, 'D' },
			{ "hours", required_argument, NULL, 'H' },
			{ "startdate", required_argument, NULL, 'S' },
			{ "enddate", required_argument, NULL, 'E' },
			{ "out", required_argument, NULL, 'o' },
			{ "debug", required_argument, NULL, 'd' },
			{ 0,0,0,0 }
		};

		int c = getopt_long(argc, argv, "hv+:qc:k:p;u:g:D:H:S:E:o:d:", long_opts, NULL);

		/* Note: "breaking" from case terminates loop */
		switch (c)
		{
			case EOF:	/* end of flags */
				break;

			case 0: /* long option already handled */
				continue;

			case ':':	/* diagnostic already printed by getopt_long */
			case '?':	/* diagnostic already printed by getopt_long */
			case 'h':	/* --help */
				usage(NULL);
				status = 1;
				goto end;

			case 'v':	/* --version */
				printf("openac (strongSwan %s)\n", VERSION);
				status = 0;
				goto end;

			case '+':	/* --optionsfrom <filename> */
				{
					char path[BUF_LEN];

					if (*optarg == '/')	/* absolute pathname */
					{
						strncpy(path, optarg, BUF_LEN);
						path[BUF_LEN-1] = '\0';
					}
					else			/* relative pathname */
					{
						snprintf(path, BUF_LEN, "%s/%s", OPENAC_PATH, optarg);
					}
					if (!options->from(options, path, &argc, &argv, optind))
					{
						status = 1;
						goto end;
					}
				}
				continue;

			case 'q':	/* --quiet */
				stderr_quiet = TRUE;
				continue;

			case 'c':	/* --cert */
				certfile = optarg;
				continue;

			case 'k':	/* --key */
				keyfile = optarg;
				continue;

			case 'p':	/* --key */
				if (strlen(optarg) >= BUF_LEN)
				{
					usage("passphrase too long");
					goto end;
				}
				strncpy(passphrase.ptr, optarg, BUF_LEN);
				passphrase.len = min(strlen(optarg), BUF_LEN);
				continue;

			case 'u':	/* --usercert */
				usercertfile = optarg;
				continue;

			case 'g':	/* --groups */
				groups = optarg;
				continue;

			case 'D':	/* --days */
				if (optarg == NULL || !isdigit(optarg[0]))
				{
					usage("missing number of days");
					goto end;
				}
				else
				{
					char *endptr;
					long days = strtol(optarg, &endptr, 0);

					if (*endptr != '\0' || endptr == optarg || days <= 0)
					{
						usage("<days> must be a positive number");
						goto end;
					}
					validity += 24*3600*days;
				}
				continue;

			case 'H':	/* --hours */
				if (optarg == NULL || !isdigit(optarg[0]))
				{
					usage("missing number of hours");
					goto end;
				}
				else
				{
					char *endptr;
					long hours = strtol(optarg, &endptr, 0);

					if (*endptr != '\0' || endptr == optarg || hours <= 0)
					{
						usage("<hours> must be a positive number");
						goto end;
					}
					validity += 3600*hours;
				}
				continue;

			case 'S':	/* --startdate */
				if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
				{
					usage("date format must be YYYYMMDDHHMMSSZ");
					goto end;
				}
				else
				{
					chunk_t date = { optarg, 15 };

					notBefore = asn1_to_time(&date, ASN1_GENERALIZEDTIME);
				}
				continue;

			case 'E':	/* --enddate */
				if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
				{
					usage("date format must be YYYYMMDDHHMMSSZ");
					goto end;
				}
				else
				{
					chunk_t date = { optarg, 15 };
					notAfter = asn1_to_time(&date, ASN1_GENERALIZEDTIME);
				}
				continue;

			case 'o':	/* --out */
				outfile = optarg;
				continue;

			case 'd':	/* --debug */
				debug_level = atoi(optarg);
				continue;

			default:
				usage("");
				status = 0;
				goto end;
		}
		/* break from loop */
		break;
	}

	if (optind != argc)
	{
		usage("unexpected argument");
		goto end;
	}

	DBG1(DBG_LIB, "starting openac (strongSwan Version %s)", VERSION);

	/* load the signer's RSA private key */
	if (keyfile != NULL)
	{
		mem_cred_t *mem;
		shared_key_t *shared;

		mem = mem_cred_create();
		lib->credmgr->add_set(lib->credmgr, &mem->set);
		shared = shared_key_create(SHARED_PRIVATE_KEY_PASS,
								   chunk_clone(passphrase));
		mem->add_shared(mem, shared, NULL);
		signerKey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
									   BUILD_FROM_FILE, keyfile,
									   BUILD_END);
		lib->credmgr->remove_set(lib->credmgr, &mem->set);
		mem->destroy(mem);
		if (signerKey == NULL)
		{
			goto end;
		}
		DBG1(DBG_LIB, "  loaded private key file '%s'", keyfile);
	}

	/* load the signer's X.509 certificate */
	if (certfile != NULL)
	{
		signerCert = lib->creds->create(lib->creds,
										CRED_CERTIFICATE, CERT_X509,
										BUILD_FROM_FILE, certfile,
										BUILD_END);
		if (signerCert == NULL)
		{
			goto end;
		}
	}

	/* load the users's X.509 certificate */
	if (usercertfile != NULL)
	{
		userCert = lib->creds->create(lib->creds,
									  CRED_CERTIFICATE, CERT_X509,
									  BUILD_FROM_FILE, usercertfile,
									  BUILD_END);
		if (userCert == NULL)
		{
			goto end;
		}
	}

	/* compute validity interval */
	validity = (validity)? validity : DEFAULT_VALIDITY;
	notBefore = (notBefore == UNDEFINED_TIME) ? time(NULL) : notBefore;
	notAfter =  (notAfter  == UNDEFINED_TIME) ? time(NULL) + validity : notAfter;

	/* build and parse attribute certificate */
	if (userCert != NULL && signerCert != NULL && signerKey != NULL &&
		outfile != NULL)
	{
		/* read the serial number and increment it by one */
		serial = read_serial();

		attr_cert = lib->creds->create(lib->creds,
							CRED_CERTIFICATE, CERT_X509_AC,
							BUILD_CERT, userCert,
							BUILD_NOT_BEFORE_TIME, notBefore,
							BUILD_NOT_AFTER_TIME, notAfter,
							BUILD_SERIAL, serial,
							BUILD_IETF_GROUP_ATTR, groups,
							BUILD_SIGNING_CERT, signerCert,
							BUILD_SIGNING_KEY, signerKey,
							BUILD_END);
		if (!attr_cert)
		{
			goto end;
		}

		/* write the attribute certificate to file */
		if (attr_cert->get_encoding(attr_cert, CERT_ASN1_DER, &attr_chunk))
		{
			if (chunk_write(attr_chunk, outfile, "attribute cert", 0022, TRUE))
			{
				write_serial(serial);
				status = 0;
			}
		}
	}
	else
	{
		usage("some of the mandatory parameters --usercert --cert --key --out "
			  "are missing");
	}

end:
	/* delete all dynamically allocated objects */
	DESTROY_IF(signerKey);
	DESTROY_IF(signerCert);
	DESTROY_IF(userCert);
	DESTROY_IF(attr_cert);
	free(attr_chunk.ptr);
	free(serial.ptr);
	closelog();
	dbg = dbg_default;
	options->destroy(options);
	exit(status);
}
