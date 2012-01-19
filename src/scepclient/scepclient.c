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

#include <freeswan.h>

#include <library.h>
#include <debug.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <utils/optionsfrom.h>
#include <utils/enumerator.h>
#include <utils/linked_list.h>
#include <crypto/hashers/hasher.h>
#include <crypto/crypters/crypter.h>
#include <crypto/proposal/proposal_keywords.h>
#include <credentials/keys/private_key.h>
#include <credentials/keys/public_key.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/pkcs10.h>
#include <plugins/plugin.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"
#include "../pluto/certs.h"
#include "../pluto/pkcs7.h"

#include "scep.h"

/*
 * definition of some defaults
 */

/* default name of DER-encoded PKCS#1 private key file */
#define DEFAULT_FILENAME_PKCS1          "myKey.der"

/* default name of DER-encoded PKCS#10 certificate request file */
#define DEFAULT_FILENAME_PKCS10         "myReq.der"

/* default name of DER-encoded PKCS#7 file */
#define DEFAULT_FILENAME_PKCS7          "pkcs7.der"

/* default name of DER-encoded self-signed X.509 certificate file */
#define DEFAULT_FILENAME_CERT_SELF      "selfCert.der"

/* default name of DER-encoded X.509 certificate file */
#define DEFAULT_FILENAME_CERT           "myCert.der"

/* default name of DER-encoded CA cert file used for key encipherment */
#define DEFAULT_FILENAME_CACERT_ENC     "caCert.der"

/* default name of the der encoded CA cert file used for signature verification */
#define DEFAULT_FILENAME_CACERT_SIG     "caCert.der"

/* default prefix of the der encoded CA certificates received from the SCEP server */
#define DEFAULT_FILENAME_PREFIX_CACERT  "caCert.der"

/* default certificate validity */
#define DEFAULT_CERT_VALIDITY    5 * 3600 * 24 * 365  /* seconds */

/* default polling time interval in SCEP manual mode */
#define DEFAULT_POLL_INTERVAL    20       /* seconds */

/* default key length for self-generated RSA keys */
#define DEFAULT_RSA_KEY_LENGTH 2048       /* bits */

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

/* options read by optionsfrom */
options_t *options;

/*
 * Global variables
 */

chunk_t pkcs1;
chunk_t pkcs7;
chunk_t challengePassword;
chunk_t serialNumber;
chunk_t transID;
chunk_t fingerprint;
chunk_t encoding;
chunk_t pkcs10_encoding;
chunk_t issuerAndSubject;
chunk_t getCertInitial;
chunk_t scep_response;

linked_list_t *subjectAltNames;

identification_t *subject      = NULL;
private_key_t *private_key     = NULL;
public_key_t *public_key       = NULL;
certificate_t *x509_signer     = NULL;
certificate_t *x509_ca_enc     = NULL;
certificate_t *x509_ca_sig     = NULL;
certificate_t *pkcs10_req      = NULL;

/**
 * @brief exit scepclient
 *
 * @param status 0 = OK, 1 = general discomfort
 */
static void
exit_scepclient(err_t message, ...)
{
	int status = 0;

	DESTROY_IF(subject);
	DESTROY_IF(private_key);
	DESTROY_IF(public_key);
	DESTROY_IF(x509_signer);
	DESTROY_IF(x509_ca_enc);
	DESTROY_IF(x509_ca_sig);
	DESTROY_IF(pkcs10_req);
	subjectAltNames->destroy_offset(subjectAltNames,
								   offsetof(identification_t, destroy));
	free(pkcs1.ptr);
	free(pkcs7.ptr);
	free(serialNumber.ptr);
	free(transID.ptr);
	free(fingerprint.ptr);
	free(encoding.ptr);
	free(pkcs10_encoding.ptr);
	free(issuerAndSubject.ptr);
	free(getCertInitial.ptr);
	free(scep_response.ptr);
	options->destroy(options);

	/* print any error message to stderr */
	if (message != NULL && *message != '\0')
	{
		va_list args;
		char m[LOG_WIDTH];      /* longer messages will be truncated */

		va_start(args, message);
		vsnprintf(m, sizeof(m), message, args);
		va_end(args);

		fprintf(stderr, "error: %s\n", m);
		status = -1;
	}
	library_deinit();
	close_log();
	exit(status);
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
		"                                   <algo> = des | 3des (default) | aes128| aes192 | \n"
		"                                   aes256 | camellia128 | camellia192 | camellia256\n"
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
	char *file_out_ca_cert   = DEFAULT_FILENAME_CACERT_ENC;

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

	/* digest algorithm used by pkcs7, default is SHA-1 */
	int pkcs7_digest_alg = OID_SHA1;

	/* signature algorithm used by pkcs10, default is SHA-1 */
	hash_algorithm_t pkcs10_signature_alg = HASH_SHA1;

	/* URL of the SCEP-Server */
	char *scep_url = NULL;

	/* http request method, default is GET */
	bool http_get_request = TRUE;

	/* poll interval time in manual mode in seconds */
	u_int poll_interval = DEFAULT_POLL_INTERVAL;

	/* maximum poll time */
	u_int max_poll_time = 0;

	err_t ugh = NULL;

	/* initialize library */
	if (!library_init(NULL))
	{
		library_deinit();
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "scepclient", argv[0]))
	{
		fprintf(stderr, "integrity check of scepclient failed\n");
		library_deinit();
		exit(SS_RC_DAEMON_INTEGRITY);
	}

	/* initialize global variables */
	pkcs1             = chunk_empty;
	pkcs7             = chunk_empty;
	serialNumber      = chunk_empty;
	transID           = chunk_empty;
	fingerprint       = chunk_empty;
	encoding          = chunk_empty;
	pkcs10_encoding   = chunk_empty;
	issuerAndSubject  = chunk_empty;
	challengePassword = chunk_empty;
	getCertInitial    = chunk_empty;
	scep_response     = chunk_empty;
	subjectAltNames   = linked_list_create();
	options           = options_create();
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
		case EOF:       /* end of flags */
			break;

		case 'h':       /* --help */
			usage(NULL);

		case 'v':       /* --version */
			version();

		case 'q':       /* --quiet */
			log_to_stderr = FALSE;
			continue;

		case 'i':       /* --in <type> [= <filename>] */
			{
				char *filename = strstr(optarg, "=");

				if (filename)
				{
					/* replace '=' by '\0' */
					*filename = '\0';
					/* set pointer to start of filename */
					filename++;
				}
				if (strcaseeq("pkcs1", optarg))
				{
					filetype_in |= PKCS1;
					if (filename)
						file_in_pkcs1 = filename;
				}
				else if (strcaseeq("cacert-enc", optarg))
				{
					filetype_in |= CACERT_ENC;
					if (filename)
						file_in_cacert_enc = filename;
				}
				else if (strcaseeq("cacert-sig", optarg))
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

		case 'o':       /* --out <type> [= <filename>] */
			{
				char *filename = strstr(optarg, "=");

				if (filename)
				{
					/* replace '=' by '\0' */
					*filename = '\0';
					/* set pointer to start of filename */
					filename++;
				}
				if (strcaseeq("pkcs1", optarg))
				{
					filetype_out |= PKCS1;
					if (filename)
						file_out_pkcs1 = filename;
				}
				else if (strcaseeq("pkcs10", optarg))
				{
					filetype_out |= PKCS10;
					if (filename)
						file_out_pkcs10 = filename;
				}
				else if (strcaseeq("pkcs7", optarg))
				{
					filetype_out |= PKCS7;
					if (filename)
						file_out_pkcs7 = filename;
				}
				else if (strcaseeq("cert-self", optarg))
				{
					filetype_out |= CERT_SELF;
					if (filename)
						file_out_cert_self = filename;
				}
				else if (strcaseeq("cert", optarg))
				{
					filetype_out |= CERT;
					if (filename)
						file_out_cert = filename;
				}
				else if (strcaseeq("cacert", optarg))
				{
					request_ca_certificate = TRUE;
					if (filename)
						file_out_ca_cert = filename;
				}
				else
				{
					usage("invalid --out file type");
				}
				continue;
			}

		case 'f':       /* --force */
			force = TRUE;
			continue;

		case '+':       /* --optionsfrom <filename> */
			if (!options->from(options, optarg, &argc, &argv, optind))
			{
				exit_scepclient("optionsfrom failed");
			}
			continue;

		case 'k':        /* --keylength <length> */
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

		case 'D':       /* --days */
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

		case 'S':       /* --startdate */
			if (optarg == NULL || strlen(optarg) != 13 || optarg[12] != 'Z')
				usage("date format must be YYMMDDHHMMSSZ");
			{
				chunk_t date = { optarg, 13 };
				notBefore = asn1_to_time(&date, ASN1_UTCTIME);
			}
			continue;

		case 'E':       /* --enddate */
			if (optarg == NULL || strlen(optarg) != 13 || optarg[12] != 'Z')
				usage("date format must be YYMMDDHHMMSSZ");
			{
				chunk_t date = { optarg, 13 };
				notAfter = asn1_to_time(&date, ASN1_UTCTIME);
			}
			continue;

		case 'd':       /* --dn */
			if (distinguishedName)
				usage("only one distinguished name allowed");
			distinguishedName = optarg;
			continue;

		case 's':       /* --subjectAltName */
			{
				char *value = strstr(optarg, "=");

				if (value)
				{
					/* replace '=' by '\0' */
					*value = '\0';
					/* set pointer to start of value */
					value++;
				}

				if (strcaseeq("email", optarg) ||
					strcaseeq("dns", optarg)   ||
					strcaseeq("ip", optarg))
				{
					subjectAltNames->insert_last(subjectAltNames,
								 identification_create_from_string(value));
					continue;
				}
				else
				{
					usage("invalid --subjectAltName type");
					continue;
				}
			}

		case 'p':       /* --password */
			if (challengePassword.len > 0)
			{
				usage("only one challenge password allowed");
			}
			if (strcaseeq("%prompt", optarg))
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

		case 'u':       /* -- url */
			if (scep_url)
			{
				usage("only one URL argument allowed");
			}
			scep_url = optarg;
			continue;

		case 'm':       /* --method */
			if (strcaseeq("get", optarg))
			{
				http_get_request = TRUE;
			}
			else if (strcaseeq("post", optarg))
			{
				http_get_request = FALSE;
			}
			else
			{
				usage("invalid http request method specified");
			}
			continue;

		case 't':       /* --interval */
			poll_interval = atoi(optarg);
			if (poll_interval <= 0)
			{
				usage("invalid interval specified");
			}
			continue;

		case 'x':       /* --maxpolltime */
			max_poll_time = atoi(optarg);
			continue;

		case 'a':       /*--algorithm */
		{
			const proposal_token_t *token;

			token = proposal_get_token(optarg, strlen(optarg));
			if (token == NULL || token->type != ENCRYPTION_ALGORITHM)
			{
				usage("invalid algorithm specified");
			}
			pkcs7_symmetric_cipher = encryption_algorithm_to_oid(
										token->algorithm, token->keysize);
			if (pkcs7_symmetric_cipher == OID_UNKNOWN)
			{
				usage("unsupported encryption algorithm specified");
			}
			continue;
		}
#ifdef DEBUG
		case 'A':       /* --debug-all */
			base_debugging |= DBG_ALL;
			continue;
		case 'P':       /* debug parsing */
			base_debugging |= DBG_PARSING;
			continue;
		case 'R':       /* debug raw */
			base_debugging |= DBG_RAW;
			continue;
		case 'C':       /* debug control */
			base_debugging |= DBG_CONTROL;
			continue;
		case 'M':       /* debug control more */
			base_debugging |= DBG_CONTROLMORE;
			continue;
		case 'X':       /* debug private */
			base_debugging |= DBG_PRIVATE;
			continue;
#endif
		default:
			usage("unknown option");
		}
		/* break from loop */
		break;
	}
	cur_debugging = base_debugging;

	init_log("scepclient");

	/* load plugins, further infrastructure may need it */
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "scepclient.load", PLUGINS)))
	{
		exit_scepclient("plugin loading failed");
	}
	DBG1(DBG_LIB, "  loaded plugins: %s",
		 lib->plugins->loaded_plugins(lib->plugins));

	if ((filetype_out == 0) && (!request_ca_certificate))
	{
		usage ("--out filetype required");
	}
	if (request_ca_certificate && (filetype_out > 0 || filetype_in > 0))
	{
		usage("in CA certificate request, no other --in or --out option allowed");
	}

	/* check if url is given, if cert output defined */
	if (((filetype_out & CERT) || request_ca_certificate) && !scep_url)
	{
		usage("URL of SCEP server required");
	}

	/* check for sanity of --in/--out */
	if (!filetype_in && (filetype_in > filetype_out))
	{
		usage("cannot generate --out of given --in!");
	}

	/* get CA cert */
	if (request_ca_certificate)
	{
		char *path = concatenate_paths(CA_CERT_PATH, file_out_ca_cert);

		if (!scep_http_request(scep_url, chunk_empty, SCEP_GET_CA_CERT,
							   http_get_request, &scep_response))
		{
			exit_scepclient("did not receive a valid scep response");
		}

		if (!chunk_write(scep_response, path, "ca cert",  0022, force))
		{
			exit_scepclient("could not write ca cert file '%s'", path);
		}
		exit_scepclient(NULL); /* no further output required */
	}

	/*
	 * input of PKCS#1 file
	 */
	if (filetype_in & PKCS1)    /* load an RSA key pair from file */
	{
		char *path = concatenate_paths(PRIVATE_KEY_PATH, file_in_pkcs1);

		private_key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
										 BUILD_FROM_FILE, path, BUILD_END);
	}
	else                                /* generate an RSA key pair */
	{
		private_key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
										 BUILD_KEY_SIZE, rsa_keylength,
										 BUILD_END);
	}
	if (private_key == NULL)
	{
		exit_scepclient("no RSA private key available");
	}
	public_key = private_key->get_public_key(private_key);

	/* check for minimum key length */
	if (private_key->get_keysize(private_key) < RSA_MIN_OCTETS / BITS_PER_BYTE)
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
		subject = identification_create_from_string(distinguishedName);
		if (subject->get_type(subject) != ID_DER_ASN1_DN)
		{
			exit_scepclient("parsing of distinguished name failed");
		}

		DBG(DBG_CONTROL,
			DBG_log("building pkcs10 object:")
		)
		pkcs10_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
						CERT_PKCS10_REQUEST,
						BUILD_SIGNING_KEY, private_key,
						BUILD_SUBJECT, subject,
						BUILD_SUBJECT_ALTNAMES, subjectAltNames,
						BUILD_CHALLENGE_PWD, challengePassword,
						BUILD_DIGEST_ALG, pkcs10_signature_alg,
						BUILD_END);
		if (!pkcs10_req)
		{
			exit_scepclient("generating pkcs10 request failed");
		}
		pkcs10_req->get_encoding(pkcs10_req, CERT_ASN1_DER, &pkcs10_encoding);
		fingerprint = scep_generate_pkcs10_fingerprint(pkcs10_encoding);
		plog("  fingerprint:    %s", fingerprint.ptr);
	}

	/*
	 * output of PKCS#10 file
	 */
	if (filetype_out & PKCS10)
	{
		char *path = concatenate_paths(REQ_PATH, file_out_pkcs10);

		if (!chunk_write(pkcs10_encoding, path, "pkcs10",  0022, force))
		{
			exit_scepclient("could not write pkcs10 file '%s'", path);
		}
		filetype_out &= ~PKCS10;   /* delete PKCS10 flag */
	}

	if (!filetype_out)
	{
		exit_scepclient(NULL); /* no further output required */
	}

	/*
	 * output of PKCS#1 file
	 */
	if (filetype_out & PKCS1)
	{
		char *path = concatenate_paths(PRIVATE_KEY_PATH, file_out_pkcs1);

		DBG(DBG_CONTROL,
			DBG_log("building pkcs1 object:")
		)
		if (!private_key->get_encoding(private_key, PRIVKEY_ASN1_DER, &pkcs1) ||
			!chunk_write(pkcs1, path, "pkcs1", 0066, force))
		{
			exit_scepclient("could not write pkcs1 file '%s'", path);
		}
		filetype_out &= ~PKCS1;   /* delete PKCS1 flag */
	}

	if (!filetype_out)
	{
		exit_scepclient(NULL); /* no further output required */
	}

	scep_generate_transaction_id(public_key, &transID, &serialNumber);
	plog("  transaction ID: %.*s", (int)transID.len, transID.ptr);

	notBefore = notBefore ? notBefore : time(NULL);
	notAfter  = notAfter  ? notAfter  : (notBefore + validity);

	/* generate a self-signed X.509 certificate */
	x509_signer = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
						BUILD_SIGNING_KEY, private_key,
						BUILD_PUBLIC_KEY, public_key,
						BUILD_SUBJECT, subject,
						BUILD_NOT_BEFORE_TIME, notBefore,
						BUILD_NOT_AFTER_TIME, notAfter,
						BUILD_SERIAL, serialNumber,
						BUILD_SUBJECT_ALTNAMES, subjectAltNames,
						BUILD_END);
	if (!x509_signer)
	{
		exit_scepclient("generating certificate failed");
	}

	/*
	 * output of self-signed X.509 certificate file
	 */
	if (filetype_out & CERT_SELF)
	{
		char *path = concatenate_paths(HOST_CERT_PATH, file_out_cert_self);

		if (!x509_signer->get_encoding(x509_signer, CERT_ASN1_DER, &encoding))
		{
			exit_scepclient("encoding certificate failed");
		}
		if (!chunk_write(encoding, path, "self-signed cert", 0022, force))
		{
			exit_scepclient("could not write self-signed cert file '%s'", path);
		}
		chunk_free(&encoding);
		filetype_out &= ~CERT_SELF;   /* delete CERT_SELF flag */
	}

	if (!filetype_out)
	{
		exit_scepclient(NULL); /* no further output required */
	}

	/*
	 * load ca encryption certificate
	 */
	{
		char *path = concatenate_paths(CA_CERT_PATH, file_in_cacert_enc);

		x509_ca_enc = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
										 BUILD_FROM_FILE, path, BUILD_END);
		if (!x509_ca_enc)
		{
			exit_scepclient("could not load encryption cacert file '%s'", path);
		}
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
		pkcs7 = scep_build_request(pkcs10_encoding,
						transID, SCEP_PKCSReq_MSG,
						x509_ca_enc, pkcs7_symmetric_cipher,
						x509_signer, pkcs7_digest_alg, private_key);
	}

	/*
	 * output pkcs7 encrypted and signed certificate request
	 */
	if (filetype_out & PKCS7)
	{
		char *path = concatenate_paths(REQ_PATH, file_out_pkcs7);

		if (!chunk_write(pkcs7, path, "pkcs7 encrypted request", 0022, force))
			exit_scepclient("could not write pkcs7 file '%s'", path);
;
		filetype_out &= ~PKCS7;   /* delete PKCS7 flag */
	}

	if (!filetype_out)
	{
		exit_scepclient(NULL); /* no further output required */
	}

	/*
	 * output certificate fetch from SCEP server
	 */
	if (filetype_out & CERT)
	{
		bool stored = FALSE;
		certificate_t *cert;
		enumerator_t  *enumerator;
		char *path = concatenate_paths(CA_CERT_PATH, file_in_cacert_sig);
		time_t poll_start = 0;

		linked_list_t    *certs         = linked_list_create();
		chunk_t           envelopedData = chunk_empty;
		chunk_t           certData      = chunk_empty;
		contentInfo_t     data          = empty_contentInfo;
		scep_attributes_t attrs         = empty_scep_attributes;

		x509_ca_sig = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
										 BUILD_FROM_FILE, path, BUILD_END);
		if (!x509_ca_sig)
		{
			exit_scepclient("could not load signature cacert file '%s'", path);
		}

		if (!scep_http_request(scep_url, pkcs7, SCEP_PKI_OPERATION,
			http_get_request, &scep_response))
		{
			exit_scepclient("did not receive a valid scep response");
		}
		ugh = scep_parse_response(scep_response, transID, &data, &attrs
								 , x509_ca_sig);
		if (ugh != NULL)
		{
			exit_scepclient(ugh);
		}

		/* in case of manual mode, we are going into a polling loop */
		if (attrs.pkiStatus == SCEP_PENDING)
		{
			identification_t *issuer = x509_ca_sig->get_subject(x509_ca_sig);

			plog("  scep request pending, polling every %d seconds"
				, poll_interval);
			poll_start = time_monotonic(NULL);
			issuerAndSubject = asn1_wrap(ASN1_SEQUENCE, "cc",
									issuer->get_encoding(issuer),
									subject);
		}
		while (attrs.pkiStatus == SCEP_PENDING)
		{
			if (max_poll_time > 0
			&& (time_monotonic(NULL) - poll_start >= max_poll_time))
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

			chunk_free(&getCertInitial);
			getCertInitial = scep_build_request(issuerAndSubject
								, transID, SCEP_GetCertInitial_MSG
								, x509_ca_enc, pkcs7_symmetric_cipher
								, x509_signer, pkcs7_digest_alg, private_key);

			if (!scep_http_request(scep_url, getCertInitial, SCEP_PKI_OPERATION,
				http_get_request, &scep_response))
			{
				exit_scepclient("did not receive a valid scep response");
			}
			ugh = scep_parse_response(scep_response, transID, &data, &attrs
									 , x509_ca_sig);
			if (ugh != NULL)
			{
				exit_scepclient(ugh);
			}
		}

		if (attrs.pkiStatus != SCEP_SUCCESS)
		{
			exit_scepclient("reply status is not 'SUCCESS'");
		}

		envelopedData = data.content;

		if (data.type != OID_PKCS7_DATA
		|| !asn1_parse_simple_object(&envelopedData, ASN1_OCTET_STRING, 0, "data"))
		{
			exit_scepclient("contentInfo is not of type 'data'");
		}
		if (!pkcs7_parse_envelopedData(envelopedData, &certData
			, serialNumber, private_key))
		{
			exit_scepclient("could not decrypt envelopedData");
		}
		if (!pkcs7_parse_signedData(certData, NULL, certs, NULL, NULL))
		{
			exit_scepclient("error parsing the scep response");
		}
		chunk_free(&certData);

		/* store the end entity certificate */
		path = concatenate_paths(HOST_CERT_PATH, file_out_cert);

		enumerator = certs->create_enumerator(certs);
		while (enumerator->enumerate(enumerator, &cert))
		{
			x509_t *x509 = (x509_t*)cert;

			if (!(x509->get_flags(x509) & X509_CA))
			{
				if (stored)
				{
					exit_scepclient("multiple certs received, only first stored");
				}
				if (!cert->get_encoding(cert, CERT_ASN1_DER, &encoding) ||
					!chunk_write(encoding, path, "requested cert", 0022, force))
				{
					exit_scepclient("could not write cert file '%s'", path);
				}
				chunk_free(&encoding);
				stored = TRUE;
			}
		}
		certs->destroy_offset(certs, offsetof(certificate_t, destroy));
		filetype_out &= ~CERT;   /* delete CERT flag */
	}

	exit_scepclient(NULL);
	return -1; /* should never be reached */
}


