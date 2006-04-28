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

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/mp_defs.h"
#include "../pluto/log.h"
#include "../pluto/asn1.h"
#include "../pluto/certs.h"
#include "../pluto/x509.h"
#include "../pluto/crl.h"
#include "../pluto/keys.h"
#include "../pluto/ac.h"

#include "build.h"

#define OPENAC_PATH	"/etc/openac"
#define OPENAC_SERIAL	"/etc/openac/serial"

const char openac_version[] = "openac 0.3";

/* by default the CRL policy is lenient */
bool strict_crl_policy = FALSE;

/* by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/* by default pluto logs out after every smartcard use */
bool pkcs11_keep_state = FALSE;

static void
usage(const char *mess)
{
    if (mess != NULL && *mess != '\0')
	fprintf(stderr, "%s\n", mess);
    fprintf(stderr
	, "Usage: openac"
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

/*
 * read the last serial number from file
 */
static chunk_t
read_serial(void)
{
    MP_INT number;

    char buf[BUF_LEN];
    char bytes[BUF_LEN];

    FILE *fd = fopen(OPENAC_SERIAL, "r");

    /* serial number defaults to 0 */
    size_t len = 1;
    bytes[0] = 0x00;

    if (fd)
    {
	if (fscanf(fd, "%s", buf))
	{
	    err_t ugh = ttodata(buf, 0, 16, bytes, BUF_LEN, &len);

	    if (ugh != NULL)
		plog("  error reading serial number from %s: %s"
		    , OPENAC_SERIAL, ugh);
	}
	fclose(fd);
    }
    else
	plog("  file '%s' does not exist yet - serial number set to 01"
	    , OPENAC_SERIAL);

    /* conversion of read serial number to a multiprecision integer
     * and incrementing it by one
     * and representing it as a two's complement octet string
     */
    n_to_mpz(&number, bytes, len);
    mpz_add_ui(&number, &number, 0x01);
    serial = mpz_to_n(&number, 1 + mpz_sizeinbase(&number, 2)/BITS_PER_BYTE);
    mpz_clear(&number);

    return serial;
}

/*
 * write back the last serial number to file
 */
static void
write_serial(chunk_t serial)
{
    char buf[BUF_LEN];

    FILE *fd = fopen(OPENAC_SERIAL, "w");

    if (fd)
    {
	datatot(serial.ptr, serial.len, 16, buf, BUF_LEN);
	plog("  serial number is %s", buf);
	fprintf(fd, "%s\n", buf);
	fclose(fd);
    }
    else
	plog("  could not open file '%s' for writing", OPENAC_SERIAL);
}

/*
 * global variables accessible by both main() and build.c
 */
x509cert_t *user   = NULL;
x509cert_t *signer = NULL;

ietfAttrList_t *groups = NULL;
struct RSA_private_key *signerkey = NULL;

time_t notBefore = 0;
time_t notAfter = 0;

chunk_t serial;


int
main(int argc, char **argv)
{
    char *keyfile = NULL;
    char *certfile = NULL;
    char *usercertfile = NULL;
    char *outfile = NULL;

    cert_t signercert = empty_cert;
    cert_t usercert = empty_cert;

    chunk_t attr_cert = empty_chunk;
    x509acert_t *ac = NULL;

    const time_t default_validity = 24*3600; 	/* 24 hours */
    time_t validity = 0;

    prompt_pass_t pass;

    pass.secret[0] = '\0';
    pass.prompt = TRUE;
    pass.fd = STDIN_FILENO;

    log_to_stderr = TRUE;

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
		    strncpy(path, optarg, BUF_LEN);
		else			/* relative pathname */
		    snprintf(path, BUF_LEN, "%s/%s", OPENAC_PATH, optarg);
		optionsfrom(path, &argc, &argv, optind, stderr);
		/* does not return on error */
	    }
	    continue;

	case 'q':	/* --quiet */
	    log_to_stderr = TRUE;
	    continue;

	case 'c':	/* --cert */
	    certfile = optarg;
	    continue;

	case 'k':	/* --key */
	    keyfile = optarg;
	    continue;

	case 'p':	/* --key */
	    pass.prompt = FALSE;
	    strncpy(pass.secret, optarg, sizeof(pass.secret));
	    continue;

	case 'u':	/* --usercert */
	    usercertfile = optarg;
	    continue;

	case 'g':	/* --groups */
	    decode_groups(optarg, &groups);
	    continue;

	case 'D':	/* --days */
            if (optarg == NULL || !isdigit(optarg[0]))
                usage("missing number of days");
            {
                char *endptr;
                long days = strtol(optarg, &endptr, 0);

                if (*endptr != '\0' || endptr == optarg
                || days <= 0)
                    usage("<days> must be a positive number");
                validity += 24*3600*days;
            }
	    continue;

	case 'H':	/* --hours */
            if (optarg == NULL || !isdigit(optarg[0]))
                usage("missing number of hours");
            {
                char *endptr;
                long hours = strtol(optarg, &endptr, 0);

                if (*endptr != '\0' || endptr == optarg
                || hours <= 0)
                    usage("<hours> must be a positive number");
                validity += 3600*hours;
            }
	    continue;

	case 'S':	/* --startdate */
            if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
                usage("date format must be YYYYMMDDHHMMSSZ");
	    {
		chunk_t date = { optarg, 15 };
		notBefore = asn1totime(&date, ASN1_GENERALIZEDTIME);
	    }
	    continue;

	case 'E':	/* --enddate */
            if (optarg == NULL || strlen(optarg) != 15 || optarg[14] != 'Z')
                usage("date format must be YYYYMMDDHHMMSSZ");
	    {
		chunk_t date = { optarg, 15 };
		notAfter = asn1totime(&date, ASN1_GENERALIZEDTIME);
	    }
	    continue;

	case 'o':	/* --outt */
	    outfile = optarg;
	    continue	    ;

#ifdef DEBUG
	case 'A':	/* --debug-all */
	    base_debugging = DBG_ALL;
	    continue;
#endif
	default:
#ifdef DEBUG
	    if (c >= DBG_OFFSET)
	    {
		base_debugging |= c - DBG_OFFSET;
		continue;
	    }
#undef	    DBG_OFFSET
#endif
	    bad_case(c);
	}
	break;
    }

    init_log("openac");
    cur_debugging = base_debugging;

    if (optind != argc)
	usage("unexpected argument");

    /* load the signer's RSA private key */
    if (keyfile != NULL)
    {
	err_t ugh = NULL;

	signerkey = alloc_thing(RSA_private_key_t, "RSA private key");
	ugh = load_rsa_private_key(keyfile, &pass, signerkey);

	if (ugh != NULL)
	{
	    free_RSA_private_content(signerkey);
	    pfree(signerkey);
	    plog("%s", ugh);
	    exit(1);
	}
    }

    /* load the signer's X.509 certificate */
    if (certfile != NULL)
    {
	if (!load_cert(certfile, "signer cert", &signercert))
	    exit(1);
	signer = signercert.u.x509;
    }

    /* load the users's X.509 certificate */
    if (usercertfile != NULL)
    {
	if (!load_cert(usercertfile, "user cert", &usercert))
	    exit(1);
	user = usercert.u.x509;
    }
    
    /* compute validity interval */
    validity = (validity)? validity : default_validity;
    notBefore = (notBefore) ? notBefore : time(NULL);
    notAfter = (notAfter) ? notAfter : notBefore + validity;

    /* build and parse attribute certificate */
    if (user != NULL && signer != NULL && signerkey != NULL)
    {
	/* read the serial number and increment it by one */
	serial = read_serial();

	attr_cert = build_attr_cert();
	ac = alloc_thing(x509acert_t, "x509acert");
	*ac = empty_ac;
	parse_ac(attr_cert, ac);
	
	/* write the attribute certificate to file */
	if (write_chunk(outfile, "attribute cert", attr_cert, 0022, TRUE))
	    write_serial(serial);
    }

    /* delete all dynamic objects */
    if (signerkey != NULL)
    {
	free_RSA_private_content(signerkey);
	pfree(signerkey);
    }
    free_x509cert(signercert.u.x509);
    free_x509cert(usercert.u.x509);
    free_ietfAttrList(groups);
    free_acert(ac);
    pfree(serial.ptr);

#ifdef LEAK_DETECTIVE
    report_leaks();
#endif /* LEAK_DETECTIVE */
    close_log();
    exit(0);
}
