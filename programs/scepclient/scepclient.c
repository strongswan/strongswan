/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

/**
 * @file main.c
 * @brief scepclient main program
 */

/**
 * @mainpage SCEP for Linux strongSwan
 *
 * Documentation of SCEP for Linux StrongSwan
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <gmp.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"
#include "../pluto/oid.h"
#include "../pluto/asn1.h"
#include "../pluto/pkcs1.h"
#include "../pluto/pkcs7.h"
#include "../pluto/certs.h"
#include "../pluto/fetch.h"
#include "../pluto/rnd.h"

#include "rsakey.h"
#include "pkcs10.h"
#include "scep.h"

/*
 * definition of some defaults
 */

/* default name of DER-encoded PKCS#1 private key file */
#define DEFAULT_FILENAME_PKCS1		"myKey.der"

/* default name of DER-encoded PKCS#10 certificate request file */
#define DEFAULT_FILENAME_PKCS10		"myReq.der"

/* default name of DER-encoded PKCS#7 file */
#define DEFAULT_FILENAME_PKCS7		"pkcs7.der"

/* default name of DER-encoded self-signed X.509 certificate file */
#define DEFAULT_FILENAME_CERT_SELF	"selfCert.der"

/* default name of DER-encoded X.509 certificate file */
#define DEFAULT_FILENAME_CERT		"myCert.der"

/* default name of DER-encoded CA cert file used for key encipherment */
#define DEFAULT_FILENAME_CACERT_ENC	"caCert.der"

/* default name of the der encoded CA cert file used for signature verification */
#define DEFAULT_FILENAME_CACERT_SIG	"caCert.der"

/* default prefix of the der encoded CA certificates received from the SCEP server */
#define DEFAULT_FILENAME_PREFIX_CACERT	"caCert.der"

/* default certificate validity */
#define DEFAULT_CERT_VALIDITY	 5 * 3600 * 24 * 365  /* seconds */

/* default polling time interval in SCEP manual mode */
#define DEFAULT_POLL_INTERVAL	 20	  /* seconds */

/* default key length for self-generated RSA keys */
#define DEFAULT_RSA_KEY_LENGTH 2048	  /* bits */

/* default distinguished name */
#define DEFAULT_DN "C=CH, O=Linux strongSwan, CN="

/* challenge password buffer size */
#define MAX_PASSWORD_LENGTH 256

/* Max length of filename for tempfile */
#define MAX_TEMP_FILENAME_LENGTH 256


/* current scepclient version */
static const char *scepclient_version = "1.0";

/* by default the CRL policy is lenient */
bool strict_crl_policy = FALSE;

/* by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/* by default pluto logs out after every smartcard use */
bool pkcs11_keep_state = FALSE;


/*
 * Global variables
 */

RSA_private_key_t *private_key = NULL;

chunk_t pkcs1;
chunk_t pkcs7;
chunk_t subject;
chunk_t challengePassword;
chunk_t serialNumber;
chunk_t transID;
chunk_t fingerprint;
chunk_t issuerAndSubject;
chunk_t getCertInitial;
chunk_t scep_response;
cert_t cert;

x509cert_t *x509_signer        = NULL;
x509cert_t *x509_ca_enc        = NULL;
x509cert_t *x509_ca_sig        = NULL;
generalName_t *subjectAltNames = NULL;
pkcs10_t *pkcs10               = NULL;

/**
 * @brief exit scepclient
 *
 * The log is closed and leaks are reported
 * if LEAK_DETECTIVE is activated
 *
 * @param status 0 = OK, 1 = general discomfort
 */
static void
exit_scepclient(err_t message, ...)
{
    if (private_key != NULL)
    {
	free_RSA_private_content(private_key);
	pfree(private_key);
    }
    freeanychunk(pkcs1);
    freeanychunk(pkcs7);
    freeanychunk(subject);
    freeanychunk(serialNumber);
    freeanychunk(transID);
    freeanychunk(fingerprint);
    freeanychunk(issuerAndSubject);
    freeanychunk(getCertInitial);
    if (scep_response.ptr != NULL)
	free(scep_response.ptr);

    free_generalNames(subjectAltNames, TRUE);
    if (x509_signer != NULL)
	x509_signer->subjectAltName = NULL;

    free_x509cert(x509_signer);
    free_x509cert(x509_ca_enc);
    free_x509cert(x509_ca_sig);
    pkcs10_free(pkcs10);

#ifdef LEAK_DETECTIVE
    report_leaks();
#endif /* LEAK_DETECTIVE */
    close_log();

    /* print any error message to stderr */
    if (message != NULL && *message != '\0')
    {
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "error: %s\n", m);
	exit(-1);
    }
    exit(0);
}

/**
 * @brief prints the program version and exits
 *
 */
static void
version(void)
{
    printf("scepclient %s\n", scepclient_version);
    exit_scepclient(NULL);
}

/**
 * @brief prints the usage of the program to the stderr output
 *
 * If message is set, program is exitet with 1 (error)
 * @param message message in case of an error
 */
static void
usage(const char *message)
{
    fprintf(stderr,
	"Usage: scepclient\n"
	" --help (-h)                       show usage and exit\n"
	" --version (-v)                    show version and exit\n"
	" --quiet (-q)                      do not write log output to stderr\n"
	" --in (-i) <type>[=<filename>]     use <filename> of <type> for input \n"
	"                                   <type> = pkcs1 | cacert-enc |  cacert-sig\n"
	"                                   - if no pkcs1 input is defined, a \n"
	"                                     RSA key will be generated\n"
	"                                   - if no filename is given, default is used\n"
	" --out (-o) <type>[=<filename>]    write output of <type> to <filename>\n"
	"                                   multiple outputs are allowed\n"
	"                                   <type> = pkcs1 | pkcs10 | pkcs7 | cert-self | cert | cacert\n"
	"                                   - type cacert defines filename prefix of\n"
	"                                     received CA certificate(s)\n"
	"                                   - if no filename is given, default is used\n"
	" --optionsfrom (-+) <filename>     reads additional options from given file\n"
	" --force (-f)                      force existing file(s)\n"
	"\n"
	"Options for key generation (pkcs1):\n"
	" --keylength (-k) <bits>           key length for RSA key generation\n"
					    "(default: 2048 bits)\n"
	"\n"
	"Options for validity:\n"
	" --days (-D) <days>                validity in days\n"
	" --startdate (-S) <YYMMDDHHMMSS>Z  not valid before date\n"
	" --enddate   (-E) <YYMMDDHHMMSS>Z  not valid after date\n"
	"\n"
	"Options for request generation (pkcs10):\n"
	" --dn (-d) <dn>                    comma separated list of distinguished names\n"
	" --subjectAltName (-s) <t>=<v>     include subjectAltName in certificate request\n"
	"                                   <t> =  email | dns | ip \n"
	" --password (-p) <pw>              challenge password\n"
	"                                   - if pw is '%%prompt', password gets prompted for\n"
	" --algorithm (-a) <algo>           use specified algorithm for PKCS#7 encryption\n"
	"                                   <algo> = des-cbc | 3des-cbc (default: 3des-cbc)\n"
	"\n"
	"Options for enrollment (cert):\n"
	" --url (-u) <url>                  url of the SCEP server\n"
	" --method (-m) post | get          http request type\n"
	" --interval (-t) <seconds>         manual mode poll interval in seconds (default 20s)\n"
	" --maxpolltime (-x) <seconds>      max poll time in seconds when in manual mode\n"
	"                                   (default: unlimited)\n"
#ifdef DEBUG
	"\n"
	"Debugging output:\n"
	" --debug-all (-A)                  show everything except private\n"
	" --debug-parsing (-P)              show parsing relevant stuff\n"
	" --debug-raw (-R)                  show raw hex dumps\n"
	" --debug-control (-C)              show control flow output\n"
	" --debug-controlmore (-M)          show more control flow\n"
	" --debug-private (-X)              show sensitive data (private keys, etc.)\n"
#endif
	);
    exit_scepclient(message);
}

/**
 * @brief main of scepclient
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char **argv)
{
    /* external values */
    extern char * optarg;
    extern int optind;

    /* type of input and output files */
    typedef enum {
	PKCS1      =  0x01,
	PKCS10     =  0x02,
	PKCS7      =  0x04,
	CERT_SELF  =  0x08,
	CERT       =  0x10,
	CACERT_ENC =  0x20,
	CACERT_SIG =  0x40
    } scep_filetype_t;

    /* filetype to read from, defaults to "generate a key" */
    scep_filetype_t filetype_in = 0;

    /* filetype to write to, no default here */
    scep_filetype_t filetype_out = 0;

    /* input files */
    char *file_in_pkcs1      = DEFAULT_FILENAME_PKCS1;
    char *file_in_cacert_enc = DEFAULT_FILENAME_CACERT_ENC;
    char *file_in_cacert_sig = DEFAULT_FILENAME_CACERT_SIG;

    /* output files */
    char *file_out_pkcs1     = DEFAULT_FILENAME_PKCS1;
    char *file_out_pkcs10    = DEFAULT_FILENAME_PKCS10;
    char *file_out_pkcs7     = DEFAULT_FILENAME_PKCS7;
    char *file_out_cert_self = DEFAULT_FILENAME_CERT_SELF;
    char *file_out_cert      = DEFAULT_FILENAME_CERT;
    char *file_out_prefix_cacert = DEFAULT_FILENAME_PREFIX_CACERT;

    /* by default user certificate is requested */
    bool request_ca_certificate = FALSE;

    /* by default existing files are not overwritten */
    bool force = FALSE;

    /* length of RSA key in bits */
    u_int rsa_keylength = DEFAULT_RSA_KEY_LENGTH;

    /* validity of self-signed certificate */
    time_t validity  = DEFAULT_CERT_VALIDITY;
    time_t notBefore = 0;
    time_t notAfter  = 0;

    /* distinguished name for requested certificate, ASCII format */
    char *distinguishedName = NULL;

    /* challenge password */
    char challenge_password_buffer[MAX_PASSWORD_LENGTH];

    /* symmetric encryption algorithm used by pkcs7, default is 3DES */
    int pkcs7_symmetric_cipher = OID_3DES_EDE_CBC;

    /* digest algorithm used by pkcs7, default is MD5 */
    int pkcs7_digest_alg = OID_MD5;

    /* signature algorithm used by pkcs10, default is MD5 with RSA encryption */
    int pkcs10_signature_alg = OID_MD5;

    /* URL of the SCEP-Server */
    char *scep_url = NULL;

    /* http request method, default is GET */
    fetch_request_t request_type = FETCH_GET;

    /* poll interval time in manual mode in seconds */
    u_int poll_interval = DEFAULT_POLL_INTERVAL;

    /* maximum poll time */
    u_int max_poll_time = 0;

    err_t ugh = NULL;

    /* initialize global variables */
    pkcs1             = empty_chunk;
    pkcs7             = empty_chunk;
    serialNumber      = empty_chunk;
    transID           = empty_chunk;
    fingerprint       = empty_chunk;
    issuerAndSubject  = empty_chunk;
    challengePassword = empty_chunk;
    getCertInitial    = empty_chunk;
    scep_response     = empty_chunk;
    log_to_stderr     = TRUE;

    for (;;)
    {
	static const struct option long_opts[] = {
	    /* name, has_arg, flag, val */
	    { "help", no_argument, NULL, 'h' },
	    { "version", no_argument, NULL, 'v' },
	    { "optionsfrom", required_argument, NULL, '+' },
	    { "quiet", no_argument, NULL, 'q' },
	    { "in", required_argument, NULL, 'i' },
	    { "out", required_argument, NULL, 'o' },
	    { "force", no_argument, NULL, 'f' },
	    { "keylength", required_argument, NULL, 'k' },
	    { "dn", required_argument, NULL, 'd' },
	    { "days", required_argument, NULL, 'D' },
	    { "startdate", required_argument, NULL, 'S' },
	    { "enddate", required_argument, NULL, 'E' },
	    { "subjectAltName", required_argument, NULL, 's' },
	    { "password", required_argument, NULL, 'p' },
	    { "algorithm", required_argument, NULL, 'a' },
	    { "url", required_argument, NULL, 'u' },
	    { "method", required_argument, NULL, 'm' },
	    { "interval", required_argument, NULL, 't' },
	    { "maxpolltime", required_argument, NULL, 'x' },
#ifdef DEBUG
	    { "debug-all", no_argument, NULL, 'A' },
	    { "debug-parsing", no_argument, NULL, 'P'},
	    { "debug-raw", no_argument, NULL, 'R'},
	    { "debug-control", no_argument, NULL, 'C'},
	    { "debug-controlmore", no_argument, NULL, 'M'},
	    { "debug-private", no_argument, NULL, 'X'},
#endif
	    { 0,0,0,0 }
	};

	/* parse next option */
	int c = getopt_long(argc, argv, "hv+:qi:o:fk:d:s:p:a:u:m:t:x:APRCMS", long_opts, NULL);

	switch (c)
	{
	case EOF:	/* end of flags */
	    break;

	case 'h':	/* --help */
	    usage(NULL);

	case 'v':	/* --version */
	    version();

	case 'q':	/* --quiet */
	    log_to_stderr = FALSE;
	    continue;

	case 'i':	/* --in <type> [= <filename>] */
	    {
		char *filename = strstr(optarg, "=");

		if (filename)
		{
		    /* replace '=' by '\0' */
		    *filename = '\0';
		    /* set pointer to start of filename */
		    filename++;
		}
		if (strcasecmp("pkcs1", optarg) == 0)
		{
		    filetype_in |= PKCS1;
		    if (filename)
			file_in_pkcs1 = filename;
		}
		else if (strcasecmp("cacert-enc", optarg) == 0)
		{
		    filetype_in |= CACERT_ENC;
		    if (filename)
			file_in_cacert_enc = filename;
		}
		else if (strcasecmp("cacert-sig", optarg) == 0)
		{
		    filetype_in |= CACERT_SIG;
		    if (filename)
			 file_in_cacert_sig = filename;
		}
		else
		{
		    usage("invalid --in file type");
		}
		continue;
	    }

	case 'o':	/* --out <type> [= <filename>] */
	    {
		char *filename = strstr(optarg, "=");

		if (filename)
		{
		    /* replace '=' by '\0' */
		    *filename = '\0';
		    /* set pointer to start of filename */
		    filename++;
		}
		if (strcasecmp("pkcs1", optarg) == 0)
		{
		    filetype_out |= PKCS1;
		    if (filename)
			file_out_pkcs1 = filename;
		}
		else if (strcasecmp("pkcs10", optarg) == 0)
		{
		    filetype_out |= PKCS10;
		    if (filename)
			file_out_pkcs10 = filename;
		}
		else if (strcasecmp("pkcs7", optarg) == 0)
		{
		    filetype_out |= PKCS7;
		    if (filename)
			file_out_pkcs7 = filename;
		}
		else if (strcasecmp("cert-self", optarg) == 0)
		{
		    filetype_out |= CERT_SELF;
		    if (filename)
			file_out_cert_self = filename;
		}
		else if (strcasecmp("cert", optarg) == 0)
		{
		    filetype_out |= CERT;
		    if (filename)
			file_out_cert = filename;
		}
		else if (strcasecmp("cacert", optarg) == 0)
		{
		    request_ca_certificate = TRUE;
		    if (filename)
			file_out_prefix_cacert = filename;
		}
		else
		{
		    usage("invalid --out file type");
		}
		continue;
	    }
	
	case 'f':	/* --force */
	    force = TRUE;
	    continue;

	case '+':	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* does not return on error */
	    continue;

	case 'k':	 /* --keylength <length> */
	    {
		div_t q;

		rsa_keylength = atoi(optarg);
		if (rsa_keylength == 0)
		    usage("invalid keylength");

		/* check if key length is a multiple of 8 bits */
		q = div(rsa_keylength, 2*BITS_PER_BYTE);
		if (q.rem != 0)
		{
		    exit_scepclient("keylength is not a multiple of %d bits!"
			, 2*BITS_PER_BYTE);
		}
		continue;
	    }

	case 'D':	/* --days */
	    if (optarg == NULL || !isdigit(optarg[0]))
		usage("missing number of days");
	    {
		char *endptr;
		long days = strtol(optarg, &endptr, 0);

		if (*endptr != '\0' || endptr == optarg
		|| days <= 0)
		    usage("<days> must be a positive number");
		validity = 24*3600*days;
	    }
	    continue;

	case 'S':	/* --startdate */
            if (optarg == NULL || strlen(optarg) != 13 || optarg[12] != 'Z')
                usage("date format must be YYMMDDHHMMSSZ");
	    {
		chunk_t date = { optarg, 13 };
		notBefore = asn1totime(&date, ASN1_UTCTIME);
	    }
	    continue;

	case 'E':	/* --enddate */
            if (optarg == NULL || strlen(optarg) != 13 || optarg[12] != 'Z')
                usage("date format must be YYMMDDHHMMSSZ");
	    {
		chunk_t date = { optarg, 13 };
		notAfter = asn1totime(&date, ASN1_UTCTIME);
	    }
	    continue;

	case 'd':	/* --dn */
	    if (distinguishedName)
		usage("only one distinguished name allowed");
	    distinguishedName = optarg;
	    continue;

	case 's':	/* --subjectAltName */
	    {
		generalNames_t kind;
		char *value = strstr(optarg, "=");

		if (value)
		{
		    /* replace '=' by '\0' */
		    *value = '\0';
		    /* set pointer to start of value */
		    value++;
		}

		if (!strcasecmp("email", optarg))
		    kind = GN_RFC822_NAME;
		else if (!strcasecmp("dns", optarg))
		    kind = GN_DNS_NAME;
		else if (!strcasecmp("ip", optarg))
		    kind = GN_IP_ADDRESS;
		else
		{
		    usage("invalid --subjectAltName type");
		    continue;
		}
		pkcs10_add_subjectAltName(&subjectAltNames, kind, value);
		continue;
	    }

	case 'p':	/* --password */
	    if (challengePassword.len > 0)
		usage("only one challenge password allowed");

	    if (strcasecmp("%prompt", optarg) == 0)
	    {
		printf("Challenge password: ");
		if (fgets(challenge_password_buffer, sizeof(challenge_password_buffer)-1, stdin))
		{
		    challengePassword.ptr = challenge_password_buffer;
		    /* discard the terminating '\n' from the input */
		    challengePassword.len = strlen(challenge_password_buffer) - 1;
		}
		else
		{
		    usage("challenge password could not be read");
		}
	    }
	    else
	    {
		challengePassword.ptr = optarg;
		challengePassword.len = strlen(optarg);
	    }
	    continue;

	case 'u':	/* -- url */
	    if (scep_url)
		usage("only one URL argument allowed");
	    scep_url = optarg;
	    continue;

	case 'm':	/* --method */
	    if (strcasecmp("post", optarg) == 0)
		request_type = FETCH_POST;
	    else if (strcasecmp("get", optarg) == 0)
		request_type = FETCH_GET;
	    else
		usage("invalid http request method specified");
	    continue;

	case 't':	/* --interval */
	    poll_interval = atoi(optarg);
	    if (poll_interval <= 0)
		usage("invalid interval specified");
	    continue;

	case 'x':	/* --maxpolltime */
	    max_poll_time = atoi(optarg);
	    if (max_poll_time < 0)
		usage("invalid maxpolltime specified");
	    continue;

	case 'a':	/*--algorithm */
	    if (strcasecmp("des-cbc", optarg) == 0)
		pkcs7_symmetric_cipher = OID_DES_CBC;
	    else if (strcasecmp("3des-cbc", optarg) == 0)
		pkcs7_symmetric_cipher = OID_3DES_EDE_CBC;
	    else
		usage("invalid encryption algorithm specified");
	    continue;
#ifdef DEBUG
	case 'A':	/* --debug-all */
	    base_debugging |= DBG_ALL;
	    continue;
	case 'P':	/* debug parsing */
	    base_debugging |= DBG_PARSING;
	    continue;
	case 'R':	/* debug raw */
	    base_debugging |= DBG_RAW;
	    continue;
	case 'C':	/* debug control */
	    base_debugging |= DBG_CONTROL;
	    continue;
	case 'M':	/* debug control more */
	    base_debugging |= DBG_CONTROLMORE;
	    continue;
	case 'X':	/* debug private */
	    base_debugging |= DBG_PRIVATE;
	    continue;
#endif
	default: 
	    usage("unknown option");
	}
	/* break from loop */
	break;
    }

    init_log("scepclient");
    cur_debugging = base_debugging;
    init_rnd_pool();
    init_fetch();

    if ((filetype_out == 0) && (!request_ca_certificate))
	usage ("--out filetype required");

    if (request_ca_certificate && (filetype_out > 0 || filetype_in > 0))
	usage("in CA certificate request, no other --in or --out option allowed");

    /* check if url is given, if cert output defined */
    if (((filetype_out & CERT) || request_ca_certificate) && !scep_url)
		usage("URL of SCEP server required");

    /* check for sanity of --in/--out */
    if (!filetype_in && (filetype_in > filetype_out))
	usage("cannot generate --out of given --in!");

    /*
     * input of PKCS#1 file
     */
    private_key = alloc_thing(RSA_private_key_t, "RSA_private_key_t");

    if (filetype_in & PKCS1)	/* load an RSA key pair from file */ 
    {
	prompt_pass_t pass = { "", FALSE, STDIN_FILENO };
	const char *path = concatenate_paths(PRIVATE_KEY_PATH, file_in_pkcs1);

	ugh = load_rsa_private_key(path, &pass, private_key);
    }
    else	    			/* generate an RSA key pair */
    {
	ugh = generate_rsa_private_key(rsa_keylength, private_key);
    }
    if (ugh != NULL)
	exit_scepclient(ugh);

    /* check for minimum key length */
    if ((private_key->pub.k) < RSA_MIN_OCTETS)
    {
	exit_scepclient("length of RSA key has to be at least %d bits"
	    ,RSA_MIN_OCTETS * BITS_PER_BYTE);
    }

    /*
     * input of PKCS#10 file
     */
    if (filetype_in & PKCS10)
    {
	/* user wants to load a pkcs10 request
	 * operation is not yet supported
	 * would require a PKCS#10 parsing function

	pkcs10 = pkcs10_read_from_file(file_in_pkcs10);

         */
    }
    else
    {
	char buf[IDTOA_BUF];
	chunk_t dn = empty_chunk;

        dn.ptr = buf;

	if (distinguishedName == NULL)
	{
	    char buf[BUF_LEN];
	    int n = sprintf(buf, DEFAULT_DN);

	    /* set the common name to the hostname */
	    if (gethostname(buf + n, BUF_LEN - n) || strlen(buf) == n)
	    {
		exit_scepclient("no hostname defined, use "
				"--dn <distinguished name> option");
	    }
	    distinguishedName = buf;
	}

	DBG(DBG_CONTROL,
	    DBG_log("dn: '%s'", distinguishedName);
	)
	ugh = atodn(distinguishedName, &dn);
	if (ugh != NULL)
	    exit_scepclient(ugh);

	clonetochunk(subject, dn.ptr, dn.len, "subject dn");

	DBG(DBG_CONTROL,
	    DBG_log("building pkcs10 object:")
	)
	pkcs10 = pkcs10_build(private_key, subject, challengePassword
		    , subjectAltNames, pkcs10_signature_alg);
	scep_generate_pkcs10_fingerprint(pkcs10->request, &fingerprint);
	plog("  fingerprint:    %.*s", (int)fingerprint.len, fingerprint.ptr);
    }

    /* 
     * output of PKCS#10 file
     */
    if (filetype_out & PKCS10)
    {
	const char *path = concatenate_paths(REQ_PATH, file_out_pkcs10);

	if (!write_chunk(path, "pkcs10", pkcs10->request, 0022, force))
	    exit_scepclient("could not write pkcs10 file '%s'", path);

	filetype_out &= ~PKCS10;   /* delete PKCS10 flag */
    }

    if (!filetype_out)
	exit_scepclient(NULL); /* no further output required */

    /*
     * output of PKCS#1 file
     */
    if (filetype_out & PKCS1)
    {
	const char *path = concatenate_paths(PRIVATE_KEY_PATH, file_out_pkcs1);

	DBG(DBG_CONTROL,
	    DBG_log("building pkcs1 object:")
	)
	pkcs1 = pkcs1_build_private_key(private_key);

	if (!write_chunk(path, "pkcs1", pkcs1, 0066, force))
	    exit_scepclient("could not write pkcs1 file '%s'", path);

	filetype_out &= ~PKCS1;   /* delete PKCS1 flag */
    }

    if (!filetype_out)
	exit_scepclient(NULL); /* no further output required */

    scep_generate_transaction_id((const RSA_public_key_t *)private_key
	, &transID, &serialNumber);
    plog("  transaction ID: %.*s", (int)transID.len, transID.ptr);

    /* generate a self-signed X.509 certificate */
    x509_signer = alloc_thing(x509cert_t, "signer cert");
    *x509_signer = empty_x509cert;
    x509_signer->serialNumber = serialNumber;
    x509_signer->sigAlg = OID_SHA1_WITH_RSA;
    x509_signer->issuer = subject;
    x509_signer->notBefore = (notBefore)? notBefore
					: time(NULL);
    x509_signer->notAfter = (notAfter)? notAfter
				      : x509_signer->notBefore + validity;
    x509_signer->subject = subject;
    x509_signer->subjectAltName = subjectAltNames;

    build_x509cert(x509_signer, (const RSA_public_key_t *)private_key
		 , private_key);

    /*
     * output of self-signed X.509 certificate file
     */
    if (filetype_out & CERT_SELF)
    {
	const char *path = concatenate_paths(HOST_CERT_PATH, file_out_cert_self);

	if (!write_chunk(path, "self-signed cert", x509_signer->certificate, 0022, force))
	    exit_scepclient("could not write self-signed cert file '%s'", path);
;
	filetype_out &= ~CERT_SELF;   /* delete CERT_SELF flag */
    }

    if (!filetype_out)
	exit_scepclient(NULL); /* no further output required */

    /*
     * load ca encryption certificate
     */
    {
	const char *path = concatenate_paths(CA_CERT_PATH, file_in_cacert_enc);
	cert_t cert;

	if (!load_cert(path, "encryption cacert", &cert))
	    exit_scepclient("could not load encryption cacert file '%s'", path);
	x509_ca_enc = cert.u.x509;
    }

    /* 
     * input of PKCS#7 file
     */
    if (filetype_in & PKCS7)
    {
	/* user wants to load a pkcs7 encrypted request
         * operation is not yet supported!
	 * would require additional parsing of transaction-id

	   pkcs7 = pkcs7_read_from_file(file_in_pkcs7);

	 */
    }
    else
    {
	DBG(DBG_CONTROL,
	    DBG_log("building pkcs7 request")
	)
	pkcs7 = scep_build_request(pkcs10->request
		    , transID, SCEP_PKCSReq_MSG
		    , x509_ca_enc, pkcs7_symmetric_cipher
		    , x509_signer, pkcs7_digest_alg, private_key);
    }

    /*
     * output pkcs7 encrypted and signed certificate request
     */
    if (filetype_out & PKCS7)
    {
	const char *path = concatenate_paths(REQ_PATH, file_out_pkcs7);

	if (!write_chunk(path, "pkcs7 encrypted request", pkcs7, 0022, force))
	    exit_scepclient("could not write pkcs7 file '%s'", path);
;
	filetype_out &= ~PKCS7;   /* delete PKCS7 flag */
    }

    if (!filetype_out)
	exit_scepclient(NULL); /* no further output required */

    /*
     * output certificate fetch from SCEP server
     */
    if (filetype_out & CERT)
    {
	const char *path = concatenate_paths(CA_CERT_PATH, file_in_cacert_sig);
	cert_t cert;
	time_t poll_start;

	x509cert_t       *certs         = NULL;
	chunk_t           envelopedData = empty_chunk;
	chunk_t           certData      = empty_chunk;
	contentInfo_t     data          = empty_contentInfo;
	scep_attributes_t attrs         = empty_scep_attributes;

	if (!load_cert(path, "signature cacert", &cert))
	    exit_scepclient("could not load signature cacert file '%s'", path);
	x509_ca_sig = cert.u.x509;

	if (!scep_http_request(scep_url, pkcs7, SCEP_PKI_OPERATION
	    , request_type, &scep_response))
	{
	    exit_scepclient("did not receive a valid scep response");
	}
        ugh = scep_parse_response(scep_response, transID, &data, &attrs
				 , x509_ca_sig);
	if (ugh != NULL)
	    exit_scepclient(ugh);

	/* in case of manual mode, we are going into a polling loop */
	if (attrs.pkiStatus == SCEP_PENDING)
	{
	    plog("  scep request pending, polling every %d seconds"
		, poll_interval);
            time(&poll_start);
	    issuerAndSubject = asn1_wrap(ASN1_SEQUENCE, "cc"
				   , x509_ca_sig->subject
				   , subject);
	}
	while (attrs.pkiStatus == SCEP_PENDING)
	{
	    if (max_poll_time > 0
	    && (time(NULL) - poll_start >= max_poll_time))
	    {
		exit_scepclient("maximum poll time reached: %d seconds"
			       , max_poll_time);
	    }
	    DBG(DBG_CONTROL,
		DBG_log("going to sleep for %d seconds", poll_interval)
	    )
	    sleep(poll_interval);
	    free(scep_response.ptr);

	    DBG(DBG_CONTROL,
		DBG_log("fingerprint:    %.*s", (int)fingerprint.len, fingerprint.ptr);
		DBG_log("transaction ID: %.*s", (int)transID.len, transID.ptr)
	    )

	    freeanychunk(getCertInitial);
	    getCertInitial = scep_build_request(issuerAndSubject
				, transID, SCEP_GetCertInitial_MSG
				, x509_ca_enc, pkcs7_symmetric_cipher
				, x509_signer, pkcs7_digest_alg, private_key);

	    if (!scep_http_request(scep_url, getCertInitial, SCEP_PKI_OPERATION
	    , request_type, &scep_response))
	    {
		exit_scepclient("did not receive a valid scep response");
	    }
            ugh = scep_parse_response(scep_response, transID, &data, &attrs
				     , x509_ca_sig);
	    if (ugh != NULL)
		exit_scepclient(ugh);
	}

	if (attrs.pkiStatus != SCEP_SUCCESS)
	{
	    exit_scepclient("reply status is not 'SUCCESS'");
	}

	envelopedData = data.content;

	if (data.type != OID_PKCS7_DATA
	|| !parse_asn1_simple_object(&envelopedData, ASN1_OCTET_STRING, 0, "data"))
	{
	    exit_scepclient("contentInfo is not of type 'data'");
	}
	if (!pkcs7_parse_envelopedData(envelopedData, &certData
	    , serialNumber, private_key))
	{
	    exit_scepclient("could not decrypt envelopedData");
	}
	if (!pkcs7_parse_signedData(certData, NULL, &certs, NULL, NULL))
        {
	    exit_scepclient("error parsing the scep response");
	}
	freeanychunk(certData);

	/* store the end entity certificate */
	path = concatenate_paths(HOST_CERT_PATH, file_out_cert);
	while (certs != NULL)
 	{
	    bool stored = FALSE;
	    x509cert_t *cert = certs;

	    if (!cert->isCA)
	    {
		if (stored)
		    exit_scepclient("multiple certs received, only first stored");
		if (!write_chunk(path, "requested cert", cert->certificate, 0022, force))
		    exit_scepclient("could not write cert file '%s'", path);
		stored = TRUE;
	    }
	    certs = certs->next;
	    free_x509cert(cert);
	}
	filetype_out &= ~CERT;   /* delete CERT flag */
    }

    exit_scepclient(NULL);
    return -1; /* should never be reached */
}


