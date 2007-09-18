/* Generation of X.509 attribute certificates
 * Copyright (C) 2002  Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2004  Andreas Steffen
 * Zuercher Hochschule Winterthur, Switzerland
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
 *
 * RCSID $Id: openac.c,v 1.18 2006/01/04 21:12:33 as Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>
#include <gmp.h>

#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/ttodata.h>
#include <crypto/ac.h>
#include <crypto/ietf_attr_list.h>
#include <utils/optionsfrom.h>

#include "build.h"

#define OPENAC_PATH   IPSEC_CONFDIR "/openac"
#define OPENAC_SERIAL IPSEC_CONFDIR "/openac/serial"

const char openac_version[] = "openac 0.4";

static void usage(const char *mess)
{
	if (mess != NULL && *mess != '\0')
	{
		fprintf(stderr, "%s\n", mess);
	}
	fprintf(stderr, "Usage: openac"
		" [--help]"
		" [--version]"
		" [--optionsfrom <filename>]"
		" [--quiet]"
#ifdef DEBUG
		" \\\n\t"
		"      [--debug-all]"
		" [--debug-parsing]"
		" [--debug-raw]"
		" [--debug-private]"
#endif
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
	exit(mess == NULL? 0 : 1);
}

/**
 * convert a chunk into a multi-precision integer
 */
static void chunk_to_mpz(chunk_t chunk, mpz_t number)
{
	mpz_import(number, chunk.len, 1, 1, 1, 0, chunk.ptr);
}

/**
 * convert a multi-precision integer into a chunk
 */
static chunk_t mpz_to_chunk(mpz_t number)
{
	chunk_t chunk;

	chunk.len = 1 + mpz_sizeinbase(number, 2)/BITS_PER_BYTE;
	chunk.ptr = mpz_export(NULL, NULL, 1, chunk.len, 1, 0, number);
	return chunk;
}

/**
 * read the last serial number from file
 */
static chunk_t read_serial(void)
{
	mpz_t number;

	char buf[BUF_LEN], buf1[BUF_LEN];
	chunk_t last_serial = { buf1, BUF_LEN};
	chunk_t serial;

	FILE *fd = fopen(OPENAC_SERIAL, "r");

	/* last serial number defaults to 0 */
	*last_serial.ptr = 0x00;
	last_serial.len = 1;

	if (fd)
	{
		if (fscanf(fd, "%s", buf))
		{
			err_t ugh = ttodata(buf, 0, 16, last_serial.ptr, BUF_LEN, &last_serial.len);

			if (ugh != NULL)
			{
				DBG1("  error reading serial number from %s: %s",
		    		 OPENAC_SERIAL, ugh);
			}
		}
		fclose(fd);
	}
	else
	{
		DBG1("  file '%s' does not exist yet - serial number set to 01", OPENAC_SERIAL);
	}

	/**
	 * conversion of read serial number to a multiprecision integer
	 * and incrementing it by one
	 * and representing it as a two's complement octet string
	 */
	printf("last_serial: '%#B'\n", &last_serial);
	mpz_init(number);
	chunk_to_mpz(last_serial, number);
	mpz_add_ui(number, number, 0x01);
	serial = mpz_to_chunk(number);
	printf("serial: '%#B'\n", &serial);
	mpz_clear(number);

	return serial;
}

/**
 * write back the last serial number to file
 */
static void write_serial(chunk_t serial)
{
	FILE *fd = fopen(OPENAC_SERIAL, "w");

	if (fd)
	{
		DBG1("  serial number is %#B", &serial);
		fprintf(fd, "%#B\n", &serial);
		fclose(fd);
	}
	else
	{
		DBG1("  could not open file '%s' for writing", OPENAC_SERIAL);
	}
}

/**
 * global variables accessible by both main() and build.c
 */
x509_t *usercert   = NULL;
x509_t *signercert = NULL;

linked_list_t *groups = NULL;
rsa_private_key_t *signerkey = NULL;

time_t notBefore = UNDEFINED_TIME;
time_t notAfter = UNDEFINED_TIME;

chunk_t serial;

int main(int argc, char **argv)
{
	char *keyfile = NULL;
	char *certfile = NULL;
	char *usercertfile = NULL;
	char *outfile = NULL;
	char buf[BUF_LEN];

	chunk_t passphrase = { buf, 0 };
	chunk_t attr_cert = chunk_empty;
	x509ac_t *ac = NULL;

	const time_t default_validity = 24*3600; 	/* 24 hours */
	time_t validity = 0;

	passphrase.ptr[0] = '\0';

	groups = linked_list_create();

	/* handle arguments */
	for (;;)
	{
#	define DBG_OFFSET 256
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
#ifdef DEBUG
			{ "debug-all", no_argument, NULL, 'A' },
			{ "debug-raw", no_argument, NULL, DBG_RAW + DBG_OFFSET },
			{ "debug-parsing", no_argument, NULL, DBG_PARSING + DBG_OFFSET },
			{ "debug-private", no_argument, NULL, DBG_PRIVATE + DBG_OFFSET },
#endif
			{ 0,0,0,0 }
		};
	
		int c = getopt_long(argc, argv, "hv+:qc:k:p;u:g:D:H:S:E:o:", long_opts, NULL);

		/* Note: "breaking" from case terminates loop */
		switch (c)
		{
			case EOF:	/* end of flags */
				break;

			case 0: /* long option already handled */
		 		continue;

			case ':':	/* diagnostic already printed by getopt_long */
			case '?':	/* diagnostic already printed by getopt_long */
				usage(NULL);
				break;   /* not actually reached */

			case 'h':	/* --help */
				usage(NULL);
				break;	/* not actually reached */

			case 'v':	/* --version */
				printf("%s\n", openac_version);
				exit(0);
				break;	/* not actually reached */

			case '+':	/* --optionsfrom <filename> */
				{
					char path[BUF_LEN];

					if (*optarg == '/')	/* absolute pathname */
					{
		    			strncpy(path, optarg, BUF_LEN);
					}
					else			/* relative pathname */
					{
		    			snprintf(path, BUF_LEN, "%s/%s", OPENAC_PATH, optarg);
					}
					optionsfrom(path, &argc, &argv, optind, stderr);
					/* does not return on error */
		 		}
				continue;

			case 'q':	/* --quiet */
				/* TODO log to syslog only */
				continue;

			case 'c':	/* --cert */
				certfile = optarg;
				continue;

			case 'k':	/* --key */
				keyfile = optarg;
				continue;

			case 'p':	/* --key */
				if (strlen(optarg) > BUF_LEN)
				{
					usage("passphrase too long");
				}
				strncpy(passphrase.ptr, optarg, BUF_LEN);
				passphrase.len = min(strlen(optarg), BUF_LEN);
				continue;

			case 'u':	/* --usercert */
				usercertfile = optarg;
				continue;

			case 'g':	/* --groups */
				ietfAttr_list_create_from_string(optarg, groups);
				continue;

			case 'D':	/* --days */
				if (optarg == NULL || !isdigit(optarg[0]))
				{
					usage("missing number of days");
				}
				else
				{
					char *endptr;
					long days = strtol(optarg, &endptr, 0);

					if (*endptr != '\0' || endptr == optarg || days <= 0)
					{
						usage("<days> must be a positive number");
					}
					validity += 24*3600*days;
				}
				continue;

			case 'H':	/* --hours */
				if (optarg == NULL || !isdigit(optarg[0]))
				{
					usage("missing number of hours");
				}
				else
				{
					char *endptr;
					long hours = strtol(optarg, &endptr, 0);

					if (*endptr != '\0' || endptr == optarg || hours <= 0)
					{
						usage("<hours> must be a positive number");
					}
					validity += 3600*hours;
				}
				continue;

			case 'S':	/* --startdate */
				if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
				{
					usage("date format must be YYYYMMDDHHMMSSZ");
				}
				else
				{
					chunk_t date = { optarg, 15 };

					notBefore = asn1totime(&date, ASN1_GENERALIZEDTIME);
				}
				continue;

			case 'E':	/* --enddate */
				if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
				{
					usage("date format must be YYYYMMDDHHMMSSZ");
				}
				else
				{
					chunk_t date = { optarg, 15 };
					notAfter = asn1totime(&date, ASN1_GENERALIZEDTIME);
				}
				continue;

			case 'o':	/* --outt */
				outfile = optarg;
				continue;

#ifdef DEBUG
			case 'A':	/* --debug-all */
				base_debugging = DBG_ALL;
				continue;
#endif
			default:
				usage("");
		}
		break;
	}

	if (optind != argc)
	{
		usage("unexpected argument");
	}

	/* load the signer's RSA private key */
	if (keyfile != NULL)
	{
		signerkey = rsa_private_key_create_from_file(keyfile, &passphrase);

		if (signerkey == NULL)
		{
			exit(1);
		}
	}

	/* load the signer's X.509 certificate */
	if (certfile != NULL)
	{
		signercert = x509_create_from_file(certfile, "signer cert");

		if (signercert == NULL)
		{
			exit(1);
		}
	}

	/* load the users's X.509 certificate */
	if (usercertfile != NULL)
	{
		usercert = x509_create_from_file(usercertfile, "signer cert");
		if (usercert == NULL)
		{
			exit(1);
		}
	}

	/* compute validity interval */
	validity = (validity)? validity : default_validity;
	notBefore = (notBefore) ? notBefore : time(NULL);
	notAfter = (notAfter) ? notAfter : notBefore + validity;

	/* build and parse attribute certificate */
	if (usercert != NULL && signercert != NULL && signerkey != NULL)
	{
		/* read the serial number and increment it by one */
		serial = read_serial();

		attr_cert = build_attr_cert();
		ac = x509ac_create_from_chunk(attr_cert);
	
		/* write the attribute certificate to file */
		if (chunk_write(attr_cert, outfile, "attribute cert", 0022, TRUE))
		{
			write_serial(serial);
		}
	}

	/* delete all dynamically allocated objects */
	DESTROY_IF(signerkey);
	DESTROY_IF(signercert);
	DESTROY_IF(usercert);
	DESTROY_IF(ac);
	ietfAttr_list_destroy(groups);
	free(serial.ptr);

	exit(0);
}
