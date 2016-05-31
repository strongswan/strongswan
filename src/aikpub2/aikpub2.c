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

#include <library.h>
#include <utils/debug.h>
#include <utils/optionsfrom.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>

#include <tss2/tpm20.h>
#include <tcti/tcti_socket.h>

#include <syslog.h>
#include <getopt.h>
#include <errno.h>

/* default directory where AIK keys are stored */
#define AIK_DIR							IPSEC_CONFDIR "/pts/"

/* default name of AIK private key blob */
#define DEFAULT_FILENAME_AIKPUBKEY		AIK_DIR "aikPub.der"

/* logging */
static bool log_to_stderr = TRUE;
static bool log_to_syslog = TRUE;
static level_t default_loglevel = 1;

/* options read by optionsfrom */
options_t *options;

/* global variables */
chunk_t aik_blob;
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
 * @param status 0 = OK, 1 = general discomfort
 */
static void exit_aikpub2(err_t message, ...)
{
	int status = 0;

	free(aik_blob.ptr);
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

		fprintf(stderr, "error: %s\n", m);
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
		"Usage: aikpub2 [--in <filename>|--handle <handle>] --out <filename>\n"
		"               [--force] [--quiet] [--debug <level>]\n"
		"       aikpub2 --help\n"
		"\n"
		"Options:\n"
		" --in (-i)         TSS 2.0 AIK public key blob\n"
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
 * Some symbols required by libtctisocket
 */
FILE *outFp;
uint8_t simulator = 1;

int TpmClientPrintf (uint8_t type, const char *format, ...)
{
    return 0;
}

/**
 * read the public key portion of a TSS 2.0 AIK key from NVRAM
 */
void read_public(TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public)
{
	size_t tcti_context_size;
	uint32_t sys_context_size, rval;

	TCTI_SOCKET_CONF rm_if_config = { DEFAULT_HOSTNAME,
									  DEFAULT_RESMGR_TPM_PORT
									};

	TSS2_ABI_VERSION abi_version = { TSSWG_INTEROP,
									 TSS_SAPI_FIRST_FAMILY,
									 TSS_SAPI_FIRST_LEVEL,
									 TSS_SAPI_FIRST_VERSION
								   };

	TPM2B_NAME name = { { sizeof(TPM2B_NAME)-2, } };
	TPM2B_NAME qualified_name = { { sizeof(TPM2B_NAME)-2, } };

	TSS2_TCTI_CONTEXT *tcti_context;
	TSS2_SYS_CONTEXT  *sys_context;

	TPMS_AUTH_RESPONSE session_data;
	TSS2_SYS_RSP_AUTHS sessions_data;
	TPMS_AUTH_RESPONSE *session_data_array[1];

	session_data_array[0]  = &session_data;
	sessions_data.rspAuths = &session_data_array[0];
	sessions_data.rspAuthsCount = 1;

	/* determine size of tcti context */
	rval = InitSocketTcti(NULL, &tcti_context_size, &rm_if_config, 0);
	if (rval != TSS2_RC_SUCCESS)
	{
		exit_aikpub2("could not get tcti_context size: 0x%06x", rval);
	}

	/* allocate memory for tcti context */
	tcti_context = (TSS2_TCTI_CONTEXT*)malloc(tcti_context_size);

	/* initialize tcti context */
	rval = InitSocketTcti(tcti_context, &tcti_context_size, &rm_if_config, 0);
	if (rval != TSS2_RC_SUCCESS)
	{
		exit_aikpub2("could not get tcti_context: 0x%06x", rval);
	}

	/* determine size of sys context */
	sys_context_size = Tss2_Sys_GetContextSize(0);

	/* allocate memory for sys context */
	sys_context = malloc(sys_context_size);

	/* initialize sys context */
	rval = Tss2_Sys_Initialize(sys_context, sys_context_size, tcti_context,
							   &abi_version);
	if (rval != TSS2_RC_SUCCESS)
	{
		TeardownSocketTcti(tcti_context);
		exit_aikpub2("could not get sys_context: 0x%06x", rval);
	}

	/* always send simulator platform command, ignored by true RM */
	PlatformCommand(tcti_context ,MS_SIM_POWER_ON );
	PlatformCommand(tcti_context, MS_SIM_NV_ON );

	/* read public key for a given object handle from TPM 2.0 NVRAM */
	rval = Tss2_Sys_ReadPublic(sys_context, handle, 0, public, &name,
							   &qualified_name, &sessions_data);

	PlatformCommand(tcti_context, MS_SIM_POWER_OFF);

	/* clean up connection to TPM 2.0 */
	TeardownSocketTcti(tcti_context);
	Tss2_Sys_Finalize(sys_context);
	free(sys_context);

	if (rval != TPM_RC_SUCCESS)
	{
		exit_aikpub2("could not read TSS 2.0 public key from handle 0x%08x:"
					 " 0x%06x", handle, rval);
	}
}

/**
 * @brief main of aikpub2 which generates an Attestation Identity Key (AIK)
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char *argv[])
{
	/* external values */
	extern char * optarg;
	extern int optind;

	uint32_t aik_handle = 0;
	char *aik_in_filename   = NULL;
	char *aik_out_filename = DEFAULT_FILENAME_AIKPUBKEY;
	chunk_t *aik_mapped;
	bool force = FALSE;
	hasher_t *hasher;

	/* TSS 2.0 variables */
	TPM2B_PUBLIC public = { { 0, } };

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

			case 'i':       /* --in <filename> */
				aik_in_filename = optarg;
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
	if (!aik_in_filename && !aik_handle)
	{
		usage("either --in or --handle option is required");
	}

	if (aik_handle)
	{
		/* read public key blob directly from TPM 2.0 */
		read_public(aik_handle, &public);
		aik_blob = chunk_clone(chunk_create((u_char*)&public, sizeof(public)));
	}
	else
	{
		/* read stored TPM 2.0 public key blob from a file */
		aik_mapped = chunk_map(aik_in_filename, FALSE);
		if (!aik_mapped)
		{
			exit_aikpub2("could not read TSS 2.0 public key file '%s'",
						  aik_in_filename);
		}
		aik_blob = chunk_clone(*aik_mapped);
		chunk_unmap(aik_mapped);

		if (aik_blob.len != sizeof(TPM2B_PUBLIC))
		{
			exit_aikpub2("size of aikblob is not %d bytes",
						  sizeof(TPM2B_PUBLIC));
		}
		public = *(TPM2B_PUBLIC*)aik_blob.ptr;
	}
	DBG3(DBG_LIB, "TSS 2.0 AIK blob: %B", &aik_blob);


	switch (public.t.publicArea.type)
	{
		case TPM_ALG_RSA:
		{
			TPM2B_PUBLIC_KEY_RSA *rsa;
			chunk_t aik_exponent, aik_modulus;

			rsa = &public.t.publicArea.unique.rsa;
			aik_modulus = chunk_create(rsa->t.buffer, rsa->t.size);
			aik_exponent = chunk_from_chars(0x01, 0x00, 0x01);

			/* subjectPublicKeyInfo encoding of AIK RSA key */
			if (!lib->encoding->encode(lib->encoding, PUBKEY_SPKI_ASN1_DER,
					NULL, &aik_pubkey, CRED_PART_RSA_MODULUS, aik_modulus,
					CRED_PART_RSA_PUB_EXP, aik_exponent, CRED_PART_END))
			{
				exit_aikpub2("subjectPublicKeyInfo encoding of AIK key failed");
			}
			break;
		}
		case TPM_ALG_ECC:
		{
			TPMS_ECC_POINT *ecc;
			chunk_t ecc_point;
			uint8_t *pos;

			ecc = &public.t.publicArea.unique.ecc;

			/* allocate space for bit string */
			pos = asn1_build_object(&ecc_point, ASN1_BIT_STRING,
									2 + ecc->x.t.size + ecc->y.t.size);
			/* bit string length is a multiple of octets */
			*pos++ = 0x00;
			/* uncompressed ECC point format */
			*pos++ = 0x04;
			/* copy x coordinate of ECC point */
			memcpy(pos, ecc->x.t.buffer, ecc->x.t.size);
			pos += ecc->x.t.size;
			/* copy y coordinate of ECC point */
			memcpy(pos, ecc->y.t.buffer, ecc->y.t.size);
			/* subjectPublicKeyInfo encoding of AIK ECC key */
			aik_pubkey = asn1_wrap(ASN1_SEQUENCE, "mm",
							asn1_wrap(ASN1_SEQUENCE, "mm",
								asn1_build_known_oid(OID_EC_PUBLICKEY),
								asn1_build_known_oid(ecc->x.t.size == 32 ?
										OID_PRIME256V1 : OID_SECT384R1)),
							ecc_point);
			break;
		}
		default:
			exit_aikpub2("unsupported key type");
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
