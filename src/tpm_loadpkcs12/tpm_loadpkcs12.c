/*
 * Copyright (C) 2017 Andreas Steffen
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


#define _GNU_SOURCE
#include <syslog.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include <tpm_tss.h>

#include <library.h>
#include <credentials/containers/pkcs12.h>
#include <credentials/certificates/x509.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/sets/callback_cred.h>
#include <utils/debug.h>

/* logging */
static bool log_to_stderr = TRUE;
static bool log_to_syslog = TRUE;
static level_t default_loglevel = 1;

/**
 * Global TPM 2.0 instance
 */
static tpm_tss_t *tpm;

/**
 * Global PKCS#12 object
 */
static pkcs12_t *p12;

/**
 * Callback credential set pki uses
 */
static callback_cred_t *cb_set;

/**
 * Credential set to cache entered secrets
 */
static mem_cred_t *cb_creds;

static shared_key_type_t prompted;

/**
 * Callback function to receive credentials
 */
static shared_key_t* cb(void *data, shared_key_type_t type,
						identification_t *me, identification_t *other,
						id_match_t *match_me, id_match_t *match_other)
{
	char buf[64], *label, *secret = NULL;
	shared_key_t *shared;

	if (prompted == type)
	{
		return NULL;
	}
	switch (type)
	{
		case SHARED_PIN:
			label = "Smartcard PIN";
			break;
		case SHARED_PRIVATE_KEY_PASS:
			label = "Private key passphrase";
			break;
		default:
			return NULL;
	}
	snprintf(buf, sizeof(buf), "%s: ", label);
#ifdef HAVE_GETPASS
	secret = getpass(buf);
#endif
	if (secret && strlen(secret))
	{
		prompted = type;
		if (match_me)
		{
			*match_me = ID_MATCH_PERFECT;
		}
		if (match_other)
		{
			*match_other = ID_MATCH_NONE;
		}
		shared = shared_key_create(type, chunk_clone(chunk_from_str(secret)));
		/* cache password in case it is required more than once */
		cb_creds->add_shared(cb_creds, shared, NULL);
		return shared->get_ref(shared);
	}
	return NULL;
}

/**
 * Register PIN/Passphrase callback function
 */
static void add_callback()
{
	cb_set = callback_cred_create_shared(cb, NULL);
	lib->credmgr->add_set(lib->credmgr, &cb_set->set);
	cb_creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &cb_creds->set);
}

/**
 * Unregister PIN/Passphrase callback function
 */
static void remove_callback()
{
	lib->credmgr->remove_set(lib->credmgr, &cb_creds->set);
	cb_creds->destroy(cb_creds);
	lib->credmgr->remove_set(lib->credmgr, &cb_set->set);
	cb_set->destroy(cb_set);
}

/**
 * logging function for tpm_loadpkcs12
 */
static void tpm_loadpkcs12_dbg(debug_t group, level_t level, char *fmt, ...)
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
	dbg = tpm_loadpkcs12_dbg;

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
 * @brief exit tpm_loadpkcs12
 *
 * @param status 0 = OK, -1 = general discomfort
 */
static void exit_tpm_loadpkcs12(err_t message, ...)
{
	int status = 0;

	DESTROY_IF(tpm);
	if (p12)
	{
		container_t *container = &p12->container;

		container->destroy(container);
	}

	/* print any error message to stderr */
	if (message != NULL && *message != '\0')
	{
		va_list args;
		char m[8192];

		va_start(args, message);
		vsnprintf(m, sizeof(m), message, args);
		va_end(args);

		fprintf(stderr, "tpm_loadpkcs12 error: %s\n", m);
		status = -1;
	}
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
		"Usage: tpm_loadpkcs12 --in <file> [--debug <level>] [--quiet]\n"
		"       tpm_loadpkcs12  --help\n"
		"\n"
		"Options:\n"
		" --in (-i)      binary input file with digest to be extended\n"
		" --help (-h)    show usage and exit\n"
		"\n"
		"Debugging output:\n"
		" --debug (-l)   changes the log level (-1..4, default: 1)\n"
		" --quiet (-q)   do not write log output to stderr\n"
		);
	exit_tpm_loadpkcs12(message);
}

/**
 * @brief main of tpm_loadpkcs12 which loads a PKCS#12 container and stores
 *        the key and certificates in a TPM 2.0
 *
 * @param argc number of arguments
 * @param argv pointer to the argument values
 */
int main(int argc, char *argv[])
{
	uint32_t hierarchy = 0x40000007;  /* TPM_RH_NULL */
	uint32_t handle = 0;
	char *infile = NULL;
	chunk_t id, encoding, pin = chunk_empty;
	enumerator_t *enumerator;
	public_key_t *pubkey;
	private_key_t *key;
	key_type_t type;
	certificate_t *cert;
	x509_flag_t flags;
	x509_t *x509;
	bool found, success;

	atexit(library_deinit);
	if (!library_init(NULL, "tpm_loadpkcs12"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "tpm_loadpkcs12", argv[0]))
	{
		fprintf(stderr, "integrity check of tpm_loadpkcs12 failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}

	for (;;)
	{
		static const struct option long_opts[] = {
			/* name, has_arg, flag, val */
			{ "help", no_argument, NULL, 'h' },
			{ "in", required_argument, NULL, 'i' },
			{ "pin", required_argument, NULL, 'p' },
			{ "handle", required_argument, NULL, 'H' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "debug", required_argument, NULL, 'l' },
			{ 0,0,0,0 }
		};

		/* parse next option */
		int c = getopt_long(argc, argv, "hi:ql:", long_opts, NULL);

		switch (c)
		{
			case EOF:       /* end of flags */
				break;

			case 'h':       /* --help */
				usage(NULL);

			case 'i':       /* --in <file> */
				infile = optarg;
				continue;

			case 'H':
				continue;

			case 'p':
				pin = chunk_from_str(optarg);
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

	init_log("tpm_loadpkcs12");

	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "tpm_loadpkcs12.load",
				"random pem openssl tpm")))
	{
		exit_tpm_loadpkcs12("plugin loading failed");
	}

	/* try to find a TPM */
	tpm = tpm_tss_probe(TPM_VERSION_2_0);
	if (!tpm)
	{
		exit_tpm_loadpkcs12("no TPM 2.0 found");
	}

	if (!infile)
	{
		exit_tpm_loadpkcs12("mandatory --in argument missing");
	}

	/* add callback prompting for PKCS#12 password */
	add_callback();
	atexit(remove_callback);

	p12 = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS12,
							  BUILD_FROM_FILE, infile, BUILD_END);

	if (!p12)
	{
		exit_tpm_loadpkcs12("reading PKCS#12 file failed");
	}
	printf("loaded PKCS#12 file from '%s'\n", infile);

	enumerator = p12->create_cert_enumerator(p12);
	while (enumerator->enumerate(enumerator, &cert))
	{
		x509 = (x509_t*)cert;
		flags = x509->get_flags(x509);
		printf("%scertificate:\n", (flags & X509_CA) ? "ca " : "");

		pubkey = cert->get_public_key(cert);
		if (pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_SHA1, &id))
		{
			printf("  subjectKeyIdentifier:      %#B\n", &id);
		}
		if (pubkey->get_fingerprint(pubkey, KEYID_PUBKEY_INFO_SHA1, &id))
		{
			printf("  subjectPublicKeyInfo hash: %#B\n", &id);
		}
		pubkey->destroy(pubkey);
	}
	enumerator->destroy(enumerator);

	enumerator = p12->create_key_enumerator(p12);
	found = enumerator->enumerate(enumerator, &key);
	enumerator->destroy(enumerator);

	if (!found)
	{
		exit_tpm_loadpkcs12("no private key found in PKCS#12 container");
	}
	type = key->get_type(key);

	/* print some private key information */
	printf("%N private key:\n", key_type_names, type);
	if (key->get_fingerprint(key, KEYID_PUBKEY_SHA1, &id))
	{
		printf("  subjectKeyIdentifier:      %#B\n", &id);
	}
	if (key->get_fingerprint(key, KEYID_PUBKEY_INFO_SHA1, &id))
	{
		printf("  subjectPublicKeyInfo hash: %#B\n", &id);
	}
	if (!key->get_encoding(key, PRIVKEY_ASN1_DER, &encoding))
	{
		exit_tpm_loadpkcs12("private key encoding failed");
	}
	printf("%B\n", &encoding);

	/* load private key into TPM */
	success = tpm->load_key(tpm, hierarchy, handle, pin, type, encoding);

	/* cleanup */
	chunk_clear(&encoding);
	exit_tpm_loadpkcs12(success ? NULL : "loading into TPM 2.0 failed");

	return -1; /* should never be reached */
}
