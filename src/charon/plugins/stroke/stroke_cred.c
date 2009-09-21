/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include <sys/stat.h>
#include <limits.h>
#include <glob.h>
#include <libgen.h>

#include "stroke_cred.h"
#include "stroke_shared_key.h"

#include <credentials/certificates/x509.h>
#include <credentials/certificates/crl.h>
#include <credentials/certificates/ac.h>
#include <utils/linked_list.h>
#include <utils/lexparser.h>
#include <utils/mutex.h>
#include <daemon.h>

/* configuration directories and files */
#define CONFIG_DIR IPSEC_CONFDIR
#define IPSEC_D_DIR CONFIG_DIR "/ipsec.d"
#define PRIVATE_KEY_DIR IPSEC_D_DIR "/private"
#define CERTIFICATE_DIR IPSEC_D_DIR "/certs"
#define CA_CERTIFICATE_DIR IPSEC_D_DIR "/cacerts"
#define AA_CERTIFICATE_DIR IPSEC_D_DIR "/aacerts"
#define ATTR_CERTIFICATE_DIR IPSEC_D_DIR "/acerts"
#define OCSP_CERTIFICATE_DIR IPSEC_D_DIR "/ocspcerts"
#define CRL_DIR IPSEC_D_DIR "/crls"
#define SECRETS_FILE CONFIG_DIR "/ipsec.secrets"

#define MAX_SECRETS_RECURSION 10

typedef struct private_stroke_cred_t private_stroke_cred_t;

/**
 * private data of stroke_cred
 */
struct private_stroke_cred_t {

	/**
	 * public functions
	 */
	stroke_cred_t public;

	/**
	 * list of trusted peer/signer/CA certificates (certificate_t)
	 */
	linked_list_t *certs;

	/**
	 * list of shared secrets (private_shared_key_t)
	 */
	linked_list_t *shared;

	/**
	 * list of private keys (private_key_t)
	 */
	linked_list_t *private;

	/**
	 * read-write lock to lists
	 */
	rwlock_t *lock;

	/**
	 * cache CRLs to disk?
	 */
	bool cachecrl;
};

/**
 * data to pass to various filters
 */
typedef struct {
	private_stroke_cred_t *this;
	identification_t *id;
	certificate_type_t type;
} id_data_t;

/**
 * destroy id enumerator data and unlock list
 */
static void id_data_destroy(id_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
	free(data);
}

/**
 * filter function for private key enumerator
 */
static bool private_filter(id_data_t *data,
						   private_key_t **in, private_key_t **out)
{
	private_key_t *key;
	chunk_t keyid;

	key = *in;
	if (data->id == NULL)
	{
		*out = key;
		return TRUE;
	}
	if (key->get_fingerprint(key, KEY_ID_PUBKEY_SHA1, &keyid) &&
		chunk_equals(keyid, data->id->get_encoding(data->id)))
	{
		*out = key;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implements credential_set_t.create_private_enumerator
 */
static enumerator_t* create_private_enumerator(private_stroke_cred_t *this,
							key_type_t type, identification_t *id)
{
	id_data_t *data;

	data = malloc_thing(id_data_t);
	data->this = this;
	data->id = id;

	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->private->create_enumerator(this->private),
									(void*)private_filter, data,
									(void*)id_data_destroy);
}

/**
 * filter function for certs enumerator
 */
static bool certs_filter(id_data_t *data, certificate_t **in, certificate_t **out)
{
	public_key_t *public;
	certificate_t *cert = *in;
	chunk_t keyid;

	if (data->type != CERT_ANY && data->type != cert->get_type(cert))
	{
		return FALSE;
	}
	if (data->id == NULL || cert->has_subject(cert, data->id))
	{
		*out = *in;
		return TRUE;
	}

	public = cert->get_public_key(cert);
	if (public)
	{
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &keyid) &&
			chunk_equals(keyid, data->id->get_encoding(data->id)))
		{
			public->destroy(public);
			*out = *in;
			return TRUE;
		}
		public->destroy(public);
	}
	return FALSE;
}

/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_cert_enumerator(private_stroke_cred_t *this,
							certificate_type_t cert, key_type_t key,
							identification_t *id, bool trusted)
{
	id_data_t *data;

	if (trusted && (cert == CERT_X509_CRL || cert == CERT_X509_AC))
	{
		return NULL;
	}
	data = malloc_thing(id_data_t);
	data->this = this;
	data->id = id;
	data->type = cert;

	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->certs->create_enumerator(this->certs),
									(void*)certs_filter, data,
									(void*)id_data_destroy);
}

typedef struct {
	private_stroke_cred_t *this;
	identification_t *me;
	identification_t *other;
	shared_key_type_t type;
} shared_data_t;

/**
 * free shared key enumerator data and unlock list
 */
static void shared_data_destroy(shared_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
	free(data);
}

/**
 * filter function for certs enumerator
 */
static bool shared_filter(shared_data_t *data,
						  stroke_shared_key_t **in, shared_key_t **out,
						  void **unused1, id_match_t *me,
						  void **unused2, id_match_t *other)
{
	id_match_t my_match, other_match;
	stroke_shared_key_t *stroke = *in;
	shared_key_t *shared = &stroke->shared;

	if (data->type != SHARED_ANY && shared->get_type(shared) != data->type)
	{
		return FALSE;
	}

	my_match = stroke->has_owner(stroke, data->me);
	other_match = stroke->has_owner(stroke, data->other);
	if (!my_match && !other_match)
	{
		return FALSE;
	}
	*out = shared;
	if (me)
	{
		*me = my_match;
	}
	if (other)
	{
		*other = other_match;
	}
	return TRUE;
}

/**
 * Implements credential_set_t.create_shared_enumerator
 */
static enumerator_t* create_shared_enumerator(private_stroke_cred_t *this,
							shared_key_type_t type,	identification_t *me,
							identification_t *other)
{
	shared_data_t *data = malloc_thing(shared_data_t);

	data->this = this;
	data->me = me;
	data->other = other;
	data->type = type;
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->shared->create_enumerator(this->shared),
									(void*)shared_filter, data,
									(void*)shared_data_destroy);
}

/**
 * Add a certificate to chain
 */
static certificate_t* add_cert(private_stroke_cred_t *this, certificate_t *cert)
{
	certificate_t *current;
	enumerator_t *enumerator;
	bool new = TRUE;

	this->lock->read_lock(this->lock);
	enumerator = this->certs->create_enumerator(this->certs);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current->equals(current, cert))
		{
			/* cert already in queue */
			cert->destroy(cert);
			cert = current;
			new = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (new)
	{
		this->certs->insert_last(this->certs, cert);
	}
	this->lock->unlock(this->lock);
	return cert;
}

/**
 * Implementation of stroke_cred_t.load_ca.
 */
static certificate_t* load_ca(private_stroke_cred_t *this, char *filename)
{
	certificate_t *cert;
	char path[PATH_MAX];

	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CA_CERTIFICATE_DIR, filename);
	}

	cert = lib->creds->create(lib->creds,
							  CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, path,
							  BUILD_END);
	if (cert)
	{
		x509_t *x509 = (x509_t*)cert;

		if (!(x509->get_flags(x509) & X509_CA))
		{
			DBG1(DBG_CFG, "  ca certificate '%Y' misses ca basic constraint, "
				 "discarded", cert->get_subject(cert));
			cert->destroy(cert);
			return NULL;
		}
		return (certificate_t*)add_cert(this, cert);
	}
	return NULL;
}

/**
 * Add X.509 CRL to chain
 */
static bool add_crl(private_stroke_cred_t *this, crl_t* crl)
{
	certificate_t *current, *cert = &crl->certificate;
	enumerator_t *enumerator;
	bool new = TRUE, found = FALSE;

	this->lock->write_lock(this->lock);
	enumerator = this->certs->create_enumerator(this->certs);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (current->get_type(current) == CERT_X509_CRL)
		{
			crl_t *crl_c = (crl_t*)current;
			chunk_t authkey = crl->get_authKeyIdentifier(crl);
			chunk_t authkey_c = crl_c->get_authKeyIdentifier(crl_c);

			/* if compare authorityKeyIdentifiers if available */
			if (authkey.ptr && authkey_c.ptr && chunk_equals(authkey, authkey_c))
			{
				found = TRUE;
			}
			else
			{
				identification_t *issuer = cert->get_issuer(cert);
				identification_t *issuer_c = current->get_issuer(current);

				/* otherwise compare issuer distinguished names */
				if (issuer->equals(issuer, issuer_c))
				{
					found = TRUE;
				}
			}
			if (found)
			{
				new = cert->is_newer(cert, current);
				if (new)
				{
					this->certs->remove_at(this->certs, enumerator);
				}
				else
				{
					cert->destroy(cert);
				}
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (new)
	{
		this->certs->insert_last(this->certs, cert);
	}
	this->lock->unlock(this->lock);
	return new;
}

/**
 * Add X.509 attribute certificate to chain
 */
static bool add_ac(private_stroke_cred_t *this, ac_t* ac)
{
	certificate_t *cert = &ac->certificate;

	this->lock->write_lock(this->lock);
	this->certs->insert_last(this->certs, cert);
	this->lock->unlock(this->lock);
	return TRUE;
}

/**
 * Implementation of stroke_cred_t.load_peer.
 */
static certificate_t* load_peer(private_stroke_cred_t *this, char *filename)
{
	certificate_t *cert;
	char path[PATH_MAX];

	if (*filename == '/')
	{
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/%s", CERTIFICATE_DIR, filename);
	}

	cert = lib->creds->create(lib->creds,
							  CRED_CERTIFICATE, CERT_ANY,
							  BUILD_FROM_FILE, path,
							  BUILD_END);
	if (cert)
	{
		cert = add_cert(this, cert);
		DBG1(DBG_CFG, "  loaded certificate '%Y' from "
				 "file '%s'", cert->get_subject(cert), filename);
		return cert->get_ref(cert);
	}
	DBG1(DBG_CFG, "  loading certificate from file "
		 "'%s' failed", filename);
	return NULL;
}

/**
 * load trusted certificates from a directory
 */
static void load_certdir(private_stroke_cred_t *this, char *path,
						 certificate_type_t type, x509_flag_t flag)
{
	struct stat st;
	char *file;

	enumerator_t *enumerator = enumerator_create_directory(path);

	if (!enumerator)
	{
		DBG1(DBG_CFG, "  reading directory failed");
		return;
	}

	while (enumerator->enumerate(enumerator, NULL, &file, &st))
	{
		certificate_t *cert;

		if (!S_ISREG(st.st_mode))
		{
			/* skip special file */
			continue;
		}
		switch (type)
		{
			case CERT_X509:
				if (flag & X509_CA)
				{	/* for CA certificates, we strictly require CA
					 * basicconstraints to be set */
					cert = lib->creds->create(lib->creds,
										CRED_CERTIFICATE, CERT_X509,
										BUILD_FROM_FILE, file, BUILD_END);
					if (cert)
					{
						x509_t *x509 = (x509_t*)cert;

						if (!(x509->get_flags(x509) & X509_CA))
						{
							DBG1(DBG_CFG, "  ca certificate '%Y' misses "
								 "ca basic constraint, discarded",
								 cert->get_subject(cert));
							cert->destroy(cert);
							cert = NULL;
						}
						else
						{
							DBG1(DBG_CFG, "  loaded CA certificate '%Y' from "
								 "file '%s'", cert->get_subject(cert), file);
						}
					}
					else
					{
						DBG1(DBG_CFG, "  loading CA certificate from file "
							 "'%s' failed", file);
					}
				}
				else
				{	/* for all other flags, we add them to the certificate. */
					cert = lib->creds->create(lib->creds,
										CRED_CERTIFICATE, CERT_X509,
										BUILD_FROM_FILE, file,
										BUILD_X509_FLAG, flag, BUILD_END);
					if (cert)
					{
						DBG1(DBG_CFG, "  loaded certificate '%Y' from "
								 "file '%s'", cert->get_subject(cert), file);
					}
					else
					{
						DBG1(DBG_CFG, "  loading certificate from file "
							 "'%s' failed", file);
					}
				}
				if (cert)
				{
					add_cert(this, cert);
				}
				break;
			case CERT_X509_CRL:
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509_CRL,
										  BUILD_FROM_FILE, file,
										  BUILD_END);
				if (cert)
				{
					add_crl(this, (crl_t*)cert);
					DBG1(DBG_CFG, "  loaded crl from file '%s'",  file);
				}
				else
				{
					DBG1(DBG_CFG, "  loading crl from file '%s' failed", file);
				}
				break;
			case CERT_X509_AC:
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509_AC,
										  BUILD_FROM_FILE, file,
										  BUILD_END);
				if (cert)
				{
					add_ac(this, (ac_t*)cert);
					DBG1(DBG_CFG, "  loaded attribute certificate from "
						 "file '%s'", file);
				}
				else
				{
					DBG1(DBG_CFG, "  loading attribute certificate from "
						 "file '%s' failed", file);
				}
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of credential_set_t.cache_cert.
 */
static void cache_cert(private_stroke_cred_t *this, certificate_t *cert)
{
	if (cert->get_type(cert) == CERT_X509_CRL && this->cachecrl)
	{
		/* CRLs get written to /etc/ipsec.d/crls/<authkeyId>.crl */
		crl_t *crl = (crl_t*)cert;

		cert->get_ref(cert);
		if (add_crl(this, crl))
		{
			char buf[BUF_LEN];
			chunk_t chunk, hex;

			chunk = crl->get_authKeyIdentifier(crl);
			hex = chunk_to_hex(chunk, NULL, FALSE);
			snprintf(buf, sizeof(buf), "%s/%s.crl", CRL_DIR, hex);
			free(hex.ptr);

			chunk = cert->get_encoding(cert);
			chunk_write(chunk, buf, "crl", 022, TRUE);
			free(chunk.ptr);
		}
	}
}

/**
 * Implementation of stroke_cred_t.cachecrl.
 */
static void cachecrl(private_stroke_cred_t *this, bool enabled)
{
	DBG1(DBG_CFG, "crl caching to %s %s",
		 CRL_DIR, enabled ? "enabled" : "disabled");
	this->cachecrl = enabled;
}


/**
 * Convert a string of characters into a binary secret
 * A string between single or double quotes is treated as ASCII characters
 * A string prepended by 0x is treated as HEX and prepended by 0s as Base64
 */
static err_t extract_secret(chunk_t *secret, chunk_t *line)
{
	chunk_t raw_secret;
	char delimiter = ' ';
	bool quotes = FALSE;

	if (!eat_whitespace(line))
	{
		return "missing secret";
	}

	if (*line->ptr == '\'' || *line->ptr == '"')
	{
		quotes = TRUE;
		delimiter = *line->ptr;
		line->ptr++;  line->len--;
	}

	if (!extract_token(&raw_secret, delimiter, line))
	{
		if (delimiter == ' ')
		{
			raw_secret = *line;
		}
		else
		{
			return "missing second delimiter";
		}
	}

	if (quotes)
	{
		/* treat as an ASCII string */
		*secret = chunk_clone(raw_secret);
		return NULL;
	}
	/* treat 0x as hex, 0s as base64 */
	if (raw_secret.len > 2)
	{
		if (strncasecmp("0x", raw_secret.ptr, 2) == 0)
		{
			*secret = chunk_from_hex(chunk_skip(raw_secret, 2), NULL);
			return NULL;
		}
		if (strncasecmp("0s", raw_secret.ptr, 2) == 0)
		{
			*secret = chunk_from_base64(chunk_skip(raw_secret, 2), NULL);
			return NULL;
		}
	}
	*secret = chunk_clone(raw_secret);
	return NULL;
}

/**
 * Data to pass to passphrase_cb
 */
typedef struct {
	/** socket we use for prompting */
	FILE *prompt;
	/** private key file */
	char *file;
	/** buffer for passphrase */
	char buf[256];
} passphrase_cb_data_t;

/**
 * Passphrase callback to read from whack fd
 */
chunk_t passphrase_cb(passphrase_cb_data_t *data, int try)
{
	chunk_t secret = chunk_empty;;

	if (try > 5)
	{
		fprintf(data->prompt, "invalid passphrase, too many trials\n");
		return chunk_empty;
	}
	if (try == 1)
	{
		fprintf(data->prompt, "Private key '%s' is encrypted\n", data->file);
	}
	else
	{
		fprintf(data->prompt, "invalid passphrase\n");
	}
	fprintf(data->prompt, "Passphrase:\n");
	if (fgets(data->buf, sizeof(data->buf), data->prompt))
	{
		secret = chunk_create(data->buf, strlen(data->buf));
		if (secret.len)
		{	/* trim appended \n */
			secret.len--;
		}
	}
	return secret;
}

/**
 * reload ipsec.secrets
 */
static void load_secrets(private_stroke_cred_t *this, char *file, int level,
						 FILE *prompt)
{
	size_t bytes;
	int line_nr = 0;
	chunk_t chunk, src, line;
	FILE *fd;
	private_key_t *private;
	shared_key_t *shared;

	DBG1(DBG_CFG, "loading secrets from '%s'", file);

	fd = fopen(file, "r");
	if (fd == NULL)
	{
		DBG1(DBG_CFG, "opening secrets file '%s' failed", file);
		return;
	}

	/* TODO: do error checks */
	fseek(fd, 0, SEEK_END);
	chunk.len = ftell(fd);
	rewind(fd);
	chunk.ptr = malloc(chunk.len);
	bytes = fread(chunk.ptr, 1, chunk.len, fd);
	fclose(fd);
	src = chunk;

	if (level == 0)
	{
		this->lock->write_lock(this->lock);

		/* flush secrets on non-recursive invocation */
		while (this->shared->remove_last(this->shared,
										 (void**)&shared) == SUCCESS)
		{
			shared->destroy(shared);
		}
		while (this->private->remove_last(this->private,
										  (void**)&private) == SUCCESS)
		{
			private->destroy(private);
		}
	}

	while (fetchline(&src, &line))
	{
		chunk_t ids, token;
		shared_key_type_t type;

		line_nr++;

		if (!eat_whitespace(&line))
		{
			continue;
		}
		if (line.len > strlen("include ") &&
			strneq(line.ptr, "include ", strlen("include ")))
		{
			glob_t buf;
			char **expanded, *dir, pattern[PATH_MAX];
			u_char *pos;

			if (level > MAX_SECRETS_RECURSION)
			{
				DBG1(DBG_CFG, "maximum level of %d includes reached, ignored",
					 MAX_SECRETS_RECURSION);
				continue;
			}
			/* terminate filename by space */
			line = chunk_skip(line, strlen("include "));
			pos = memchr(line.ptr, ' ', line.len);
			if (pos)
			{
				line.len = pos - line.ptr;
			}
			if (line.len && line.ptr[0] == '/')
			{
				if (line.len + 1 > sizeof(pattern))
				{
					DBG1(DBG_CFG, "include pattern too long, ignored");
					continue;
				}
				snprintf(pattern, sizeof(pattern), "%.*s", line.len, line.ptr);
			}
			else
			{	/* use directory of current file if relative */
				dir = strdup(file);
				dir = dirname(dir);

				if (line.len + 1 + strlen(dir) + 1 > sizeof(pattern))
				{
					DBG1(DBG_CFG, "include pattern too long, ignored");
					free(dir);
					continue;
				}
				snprintf(pattern, sizeof(pattern), "%s/%.*s",
						 dir, line.len, line.ptr);
				free(dir);
			}
			if (glob(pattern, GLOB_ERR, NULL, &buf) != 0)
			{
				DBG1(DBG_CFG, "expanding file expression '%s' failed", pattern);
				globfree(&buf);
			}
			else
			{
				for (expanded = buf.gl_pathv; *expanded != NULL; expanded++)
				{
					load_secrets(this, *expanded, level + 1, prompt);
				}
			}
			globfree(&buf);
			continue;
		}

		if (line.len > 2 && strneq(": ", line.ptr, 2))
		{
			/* no ids, skip the ':' */
			ids = chunk_empty;
			line.ptr++;
			line.len--;
		}
		else if (extract_token_str(&ids, " : ", &line))
		{
			/* NULL terminate the extracted id string */
			*(ids.ptr + ids.len) = '\0';
		}
		else
		{
			DBG1(DBG_CFG, "line %d: missing ' : ' separator", line_nr);
			goto error;
		}

		if (!eat_whitespace(&line) || !extract_token(&token, ' ', &line))
		{
			DBG1(DBG_CFG, "line %d: missing token", line_nr);
			goto error;
		}
		if (match("RSA", &token) || match("ECDSA", &token))
		{
			char path[PATH_MAX];
			chunk_t filename;
			chunk_t secret = chunk_empty;
			private_key_t *key = NULL;
			key_type_t key_type = match("RSA", &token) ? KEY_RSA : KEY_ECDSA;

			err_t ugh = extract_value(&filename, &line);

			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: %s", line_nr, ugh);
				goto error;
			}
			if (filename.len == 0)
			{
				DBG1(DBG_CFG, "line %d: empty filename", line_nr);
				goto error;
			}
			if (*filename.ptr == '/')
			{
				/* absolute path name */
				snprintf(path, sizeof(path), "%.*s", filename.len, filename.ptr);
			}
			else
			{
				/* relative path name */
				snprintf(path, sizeof(path), "%s/%.*s", PRIVATE_KEY_DIR,
						 filename.len, filename.ptr);
			}

			/* check for optional passphrase */
			if (eat_whitespace(&line))
			{
				ugh = extract_secret(&secret, &line);
				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "line %d: malformed passphrase: %s", line_nr, ugh);
					goto error;
				}
			}
			if (secret.len == 7 && strneq(secret.ptr, "%prompt", 7))
			{
				if (prompt)
				{
					passphrase_cb_data_t data;

					data.prompt = prompt;
					data.file = path;
					key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
											 key_type, BUILD_FROM_FILE, path,
											 BUILD_PASSPHRASE_CALLBACK,
											 passphrase_cb, &data, BUILD_END);
				}
			}
			else
			{
				key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, key_type,
										 BUILD_FROM_FILE, path,
										 BUILD_PASSPHRASE, secret, BUILD_END);
			}
			if (key)
			{
				DBG1(DBG_CFG, "  loaded %N private key file '%s'",
					 key_type_names, key->get_type(key), path);
				this->private->insert_last(this->private, key);
			}
			else
			{
				DBG1(DBG_CFG, "  skipped private key file '%s'", path);
			}
			chunk_clear(&secret);
		}
		else if (match("PIN", &token))
		{
			chunk_t sc = chunk_empty, secret = chunk_empty;
			char smartcard[32], keyid[22], pin[32];
			private_key_t *key;
			u_int slot;

			err_t ugh = extract_value(&sc, &line);

			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: %s", line_nr, ugh);
				goto error;
			}
			if (sc.len == 0)
			{
				DBG1(DBG_CFG, "line %d: expected %%smartcard specifier", line_nr);
				goto error;
			}
			snprintf(smartcard, sizeof(smartcard), "%.*s", sc.len, sc.ptr);
			smartcard[sizeof(smartcard) - 1] = '\0';

			/* parse slot and key id. only two formats are supported.
			 * first try %smartcard<slot>:<keyid> */
			if (sscanf(smartcard, "%%smartcard%u:%s", &slot, keyid) == 2)
			{
				snprintf(smartcard, sizeof(smartcard), "%u:%s", slot, keyid);
			}
			/* then try %smartcard:<keyid> */
			else if (sscanf(smartcard, "%%smartcard:%s", keyid) == 1)
			{
				snprintf(smartcard, sizeof(smartcard), "%s", keyid);
			}
			else
			{
				DBG1(DBG_CFG, "line %d: the given %%smartcard specifier is not"
						" supported or invalid", line_nr);
				goto error;
			}

			if (!eat_whitespace(&line))
			{
				DBG1(DBG_CFG, "line %d: expected PIN", line_nr);
				goto error;
			}
			ugh = extract_secret(&secret, &line);
			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: malformed PIN: %s", line_nr, ugh);
				goto error;
			}
			snprintf(pin, sizeof(pin), "%.*s", secret.len, secret.ptr);
			pin[sizeof(pin) - 1] = '\0';

			/* we assume an RSA key */
			key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
									 BUILD_SMARTCARD_KEYID, smartcard,
									 BUILD_SMARTCARD_PIN, pin, BUILD_END);

			if (key)
			{
				DBG1(DBG_CFG, "  loaded private key from %.*s", sc.len, sc.ptr);
				this->private->insert_last(this->private, key);
			}
			memset(pin, 0, sizeof(pin));
			chunk_clear(&secret);
		}
		else if ((match("PSK", &token) && (type = SHARED_IKE)) ||
				 (match("EAP", &token) && (type = SHARED_EAP)) ||
				 (match("XAUTH", &token) && (type = SHARED_EAP)))
		{
			stroke_shared_key_t *shared_key;
			chunk_t secret = chunk_empty;
			bool any = TRUE;

			err_t ugh = extract_secret(&secret, &line);
			if (ugh != NULL)
			{
				DBG1(DBG_CFG, "line %d: malformed secret: %s", line_nr, ugh);
				goto error;
			}
			shared_key = stroke_shared_key_create(type, secret);
			DBG1(DBG_CFG, "  loaded %N secret for %s", shared_key_type_names, type,
				 ids.len > 0 ? (char*)ids.ptr : "%any");
			DBG4(DBG_CFG, "  secret: %#B", &secret);

			this->shared->insert_last(this->shared, shared_key);
			while (ids.len > 0)
			{
				chunk_t id;
				identification_t *peer_id;

				ugh = extract_value(&id, &ids);
				if (ugh != NULL)
				{
					DBG1(DBG_CFG, "line %d: %s", line_nr, ugh);
					goto error;
				}
				if (id.len == 0)
				{
					continue;
				}

				/* NULL terminate the ID string */
				*(id.ptr + id.len) = '\0';
				peer_id = identification_create_from_string(id.ptr);
				if (peer_id->get_type(peer_id) == ID_ANY)
				{
					peer_id->destroy(peer_id);
					continue;
				}

				shared_key->add_owner(shared_key, peer_id);
				any = FALSE;
			}
			if (any)
			{
				shared_key->add_owner(shared_key,
					identification_create_from_encoding(ID_ANY, chunk_empty));
			}
		}
		else
		{
			DBG1(DBG_CFG, "line %d: token must be either "
				 "RSA, ECDSA, PSK, EAP, XAUTH or PIN", line_nr);
			goto error;
		}
	}
error:
	if (level == 0)
	{
		this->lock->unlock(this->lock);
	}
	chunk_clear(&chunk);
}

/**
 * load all certificates from ipsec.d
 */
static void load_certs(private_stroke_cred_t *this)
{
	DBG1(DBG_CFG, "loading ca certificates from '%s'",
		 CA_CERTIFICATE_DIR);
	load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);

	DBG1(DBG_CFG, "loading aa certificates from '%s'",
		 AA_CERTIFICATE_DIR);
	load_certdir(this, AA_CERTIFICATE_DIR, CERT_X509, X509_AA);

	DBG1(DBG_CFG, "loading ocsp signer certificates from '%s'",
		 OCSP_CERTIFICATE_DIR);
	load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509, X509_OCSP_SIGNER);

	DBG1(DBG_CFG, "loading attribute certificates from '%s'",
		 ATTR_CERTIFICATE_DIR);
	load_certdir(this, ATTR_CERTIFICATE_DIR, CERT_X509_AC, 0);

	DBG1(DBG_CFG, "loading crls from '%s'",
		 CRL_DIR);
	load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
}

/**
 * Implementation of stroke_cred_t.reread.
 */
static void reread(private_stroke_cred_t *this, stroke_msg_t *msg, FILE *prompt)
{
	if (msg->reread.flags & REREAD_SECRETS)
	{
		DBG1(DBG_CFG, "rereading secrets");
		load_secrets(this, SECRETS_FILE, 0, prompt);
	}
	if (msg->reread.flags & REREAD_CACERTS)
	{
		DBG1(DBG_CFG, "rereading ca certificates from '%s'",
			 CA_CERTIFICATE_DIR);
		load_certdir(this, CA_CERTIFICATE_DIR, CERT_X509, X509_CA);
	}
	if (msg->reread.flags & REREAD_OCSPCERTS)
	{
		DBG1(DBG_CFG, "rereading ocsp signer certificates from '%s'",
			 OCSP_CERTIFICATE_DIR);
		load_certdir(this, OCSP_CERTIFICATE_DIR, CERT_X509,
			 X509_OCSP_SIGNER);
	}
	if (msg->reread.flags & REREAD_AACERTS)
	{
		DBG1(DBG_CFG, "rereading aa certificates from '%s'",
			 AA_CERTIFICATE_DIR);
		load_certdir(this, AA_CERTIFICATE_DIR, CERT_X509, X509_AA);
	}
	if (msg->reread.flags & REREAD_ACERTS)
	{
		DBG1(DBG_CFG, "rereading attribute certificates from '%s'",
			 ATTR_CERTIFICATE_DIR);
		load_certdir(this, ATTR_CERTIFICATE_DIR, CERT_X509_AC, 0);
	}
	if (msg->reread.flags & REREAD_CRLS)
	{
		DBG1(DBG_CFG, "rereading crls from '%s'",
			 CRL_DIR);
		load_certdir(this, CRL_DIR, CERT_X509_CRL, 0);
	}
}

/**
 * Implementation of stroke_cred_t.destroy
 */
static void destroy(private_stroke_cred_t *this)
{
	this->certs->destroy_offset(this->certs, offsetof(certificate_t, destroy));
	this->shared->destroy_offset(this->shared, offsetof(shared_key_t, destroy));
	this->private->destroy_offset(this->private, offsetof(private_key_t, destroy));
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
stroke_cred_t *stroke_cred_create()
{
	private_stroke_cred_t *this = malloc_thing(private_stroke_cred_t);

	this->public.set.create_private_enumerator = (void*)create_private_enumerator;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)cache_cert;
	this->public.reread = (void(*)(stroke_cred_t*, stroke_msg_t *msg, FILE*))reread;
	this->public.load_ca = (certificate_t*(*)(stroke_cred_t*, char *filename))load_ca;
	this->public.load_peer = (certificate_t*(*)(stroke_cred_t*, char *filename))load_peer;
	this->public.cachecrl = (void(*)(stroke_cred_t*, bool enabled))cachecrl;
	this->public.destroy = (void(*)(stroke_cred_t*))destroy;

	this->certs = linked_list_create();
	this->shared = linked_list_create();
	this->private = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	load_certs(this);
	load_secrets(this, SECRETS_FILE, 0, NULL);

	this->cachecrl = FALSE;

	return &this->public;
}

