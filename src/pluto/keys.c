/* mechanisms for preshared keys (public, private, and preshared secrets)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND     /* fix for old versions */
#endif
#endif

#include <freeswan.h>

#include <library.h>
#include <asn1/asn1.h>
#include <credentials/certificates/pgp_certificate.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/sets/callback_cred.h>

#include "constants.h"
#include "defs.h"
#include "x509.h"
#include "certs.h"
#include "smartcard.h"
#include "connections.h"
#include "state.h"
#include "lex.h"
#include "keys.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "timer.h"
#include "fetch.h"

const char *shared_secrets_file = SHARED_SECRETS_FILE;


typedef enum secret_kind_t secret_kind_t;

enum secret_kind_t {
	SECRET_PSK,
	SECRET_PUBKEY,
	SECRET_XAUTH,
	SECRET_PIN
};

typedef struct secret_t secret_t;

struct secret_t {
	linked_list_t *ids;
	secret_kind_t kind;
	union {
		chunk_t        preshared_secret;
		private_key_t *private_key;
		smartcard_t   *smartcard;
	} u;
	secret_t *next;
};

/*
 * free a public key struct
 */
static void free_public_key(pubkey_t *pk)
{
	DESTROY_IF(pk->id);
	DESTROY_IF(pk->public_key);
	DESTROY_IF(pk->issuer);
	free(pk->serial.ptr);
	free(pk);
}

secret_t *secrets = NULL;

/**
 * Find the secret associated with the combination of me and the peer.
 */
const secret_t* match_secret(identification_t *my_id, identification_t *his_id,
							 secret_kind_t kind)
{
	enum {      /* bits */
		match_default = 0x01,
		match_him     = 0x02,
		match_me      = 0x04
	};

	unsigned int best_match = 0;
	secret_t *s, *best = NULL;

	for (s = secrets; s != NULL; s = s->next)
	{
		unsigned int match = 0;

		if (s->kind != kind)
		{
			continue;
		}

		if (s->ids->get_count(s->ids) == 0)
		{
			/* a default (signified by lack of ids):
			 * accept if no more specific match found
			 */
			match = match_default;
		}
		else
		{
			/* check if both ends match ids */
			enumerator_t *enumerator;
			identification_t *id;

			enumerator = s->ids->create_enumerator(s->ids);
			while (enumerator->enumerate(enumerator, &id))
			{
				if (my_id->equals(my_id, id))
				{
					match |= match_me;
				}
				if (his_id->equals(his_id, id))
				{
					match |= match_him;
				}
			}
			enumerator->destroy(enumerator);

			/* If our end matched the only id in the list,
			 * default to matching any peer.
			 * A more specific match will trump this.
			 */
			if (match == match_me && s->ids->get_count(s->ids) == 1)
			{
				match |= match_default;
			}
		}

		switch (match)
		{
			case match_me:
				/* if this is an asymmetric (eg. public key) system,
				 * allow this-side-only match to count, even if
				 * there are other ids in the list.
				 */
				if (kind != SECRET_PUBKEY)
				{
					break;
				}
				/* FALLTHROUGH */
			case match_default:              /* default all */
			case match_me | match_default:   /* default peer */
			case match_me | match_him:       /* explicit */
				if (match == best_match)
				{
					/* two good matches are equally good: do they agree? */
					bool same = FALSE;

					switch (kind)
					{
					case SECRET_PSK:
					case SECRET_XAUTH:
						same = chunk_equals(s->u.preshared_secret,
											best->u.preshared_secret);
						break;
					case SECRET_PUBKEY:
						same = s->u.private_key->equals(s->u.private_key,
														best->u.private_key);
						break;
					default:
						bad_case(kind);
					}
					if (!same)
					{
						loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with "
							"distinct secrets match endpoints: first secret used");
						best = s;       /* list is backwards: take latest in list */
					}
				}
				else if (match > best_match)
				{
					/* this is the best match so far */
					best_match = match;
					best = s;
				}
		}
	}
	return best;
}

/**
 * Retrieves an XAUTH secret primarily based on the user ID and
 * secondarily based on the server ID
 */
bool get_xauth_secret(identification_t *user, identification_t *server,
					  chunk_t *secret)
{
	const secret_t *s;

	s = match_secret(user, server, SECRET_XAUTH);
	if (s)
	{
		*secret = chunk_clone(s->u.preshared_secret);
		return TRUE;
	}
	else
	{
		*secret = chunk_empty;
		return FALSE;
	}
}

/**
 * We match the ID (if none, the IP address). Failure is indicated by a NULL.
 */
static const secret_t* get_secret(const connection_t *c, secret_kind_t kind)
{
	identification_t *my_id, *his_id;
	const secret_t *best;

	my_id  = c->spd.this.id;

	if (his_id_was_instantiated(c))
	{
		/* roadwarrior: replace him with 0.0.0.0 */
		his_id = identification_create_from_string("%any");
	}
	else if (kind == SECRET_PSK && (c->policy & (POLICY_PSK | POLICY_XAUTH_PSK)) &&
		((c->kind == CK_TEMPLATE &&
		 c->spd.that.id->get_type(c->spd.that.id) == ID_ANY) ||
		(c->kind == CK_INSTANCE && id_is_ipaddr(c->spd.that.id))))
	{
		/* roadwarrior: replace him with 0.0.0.0 */
		his_id = identification_create_from_string("%any");
	}
	else
	{
		his_id = c->spd.that.id->clone(c->spd.that.id);
	}

	best = match_secret(my_id, his_id, kind);

	his_id->destroy(his_id);
	return best;
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t* get_preshared_secret(const connection_t *c)
{
	const secret_t *s = get_secret(c, SECRET_PSK);

	DBG(DBG_PRIVATE,
		if (s == NULL)
			DBG_log("no Preshared Key Found");
		else
			DBG_dump_chunk("Preshared Key", s->u.preshared_secret);
	)
	return s == NULL? NULL : &s->u.preshared_secret;
}

/* check the existence of a private key matching a public key contained
 * in an X.509 or OpenPGP certificate
 */
bool has_private_key(cert_t *cert)
{
	secret_t *s;
	bool has_key = FALSE;
	public_key_t *pub_key = cert->cert->get_public_key(cert->cert);

	for (s = secrets; s != NULL; s = s->next)
	{
		if (s->kind == SECRET_PUBKEY &&
			s->u.private_key->belongs_to(s->u.private_key, pub_key))
		{
			has_key = TRUE;
			break;
		}
	}
	pub_key->destroy(pub_key);
	return has_key;
}

/*
 * get the matching private key belonging to a given X.509 certificate
 */
private_key_t* get_x509_private_key(const cert_t *cert)
{
	public_key_t *public_key = cert->cert->get_public_key(cert->cert);
	private_key_t *private_key = NULL;
	secret_t *s;

	for (s = secrets; s != NULL; s = s->next)
	{

		if (s->kind == SECRET_PUBKEY &&
			s->u.private_key->belongs_to(s->u.private_key, public_key))
		{
			private_key = s->u.private_key;
			break;
		}
	}
	public_key->destroy(public_key);
	return private_key;
}

/* find the appropriate private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
private_key_t* get_private_key(const connection_t *c)
{
	const secret_t *s, *best = NULL;

	/* is a certificate assigned to this connection? */
	if (c->spd.this.cert)
	{
		certificate_t *certificate;
		public_key_t *pub_key;

		certificate = c->spd.this.cert->cert;
		pub_key = certificate->get_public_key(certificate);

		for (s = secrets; s != NULL; s = s->next)
		{
			if (s->kind == SECRET_PUBKEY &&
				s->u.private_key->belongs_to(s->u.private_key, pub_key))
			{
				best = s;
				break; /* found the private key - no sense in searching further */
			}
		}
		pub_key->destroy(pub_key);
	}
	else
	{
		best = get_secret(c, SECRET_PUBKEY);
	}
	return best ? best->u.private_key : NULL;
}

/* digest a secrets file
 *
 * The file is a sequence of records.  A record is a maximal sequence of
 * tokens such that the first, and only the first, is in the first column
 * of a line.
 *
 * Tokens are generally separated by whitespace and are key words, ids,
 * strings, or data suitable for ttodata(3).  As a nod to convention,
 * a trailing ":" on what would otherwise be a token is taken as a
 * separate token.  If preceded by whitespace, a "#" is taken as starting
 * a comment: it and the rest of the line are ignored.
 *
 * One kind of record is an include directive.  It starts with "include".
 * The filename is the only other token in the record.
 * If the filename does not start with /, it is taken to
 * be relative to the directory containing the current file.
 *
 * The other kind of record describes a key.  It starts with a
 * sequence of ids and ends with key information.  Each id
 * is an IP address, a Fully Qualified Domain Name (which will immediately
 * be resolved), or @FQDN which will be left as a name.
 *
 * The key part can be in several forms.
 *
 * The old form of the key is still supported: a simple
 * quoted strings (with no escapes) is taken as a preshred key.
 *
 * The new form starts the key part with a ":".
 *
 * For Preshared Key, use the "PSK" keyword, and follow it by a string
 * or a data token suitable for ttodata(3).
 *
 * For RSA Private Key, use the "RSA" keyword, followed by a
 * brace-enclosed list of key field keywords and data values.
 * The data values are large integers to be decoded by ttodata(3).
 * The fields are a subset of those used by BIND 8.2 and have the
 * same names.
 */

/* parse PSK from file */
static err_t process_psk_secret(chunk_t *psk)
{
	err_t ugh = NULL;

	if (*tok == '"' || *tok == '\'')
	{
		chunk_t secret = { tok + 1, flp->cur - tok  -2 };

		*psk = chunk_clone(secret);
		(void) shift();
	}
	else
	{
		char buf[BUF_LEN];      /* limit on size of binary representation of key */
		size_t sz;

		ugh = ttodatav(tok, flp->cur - tok, 0, buf, sizeof(buf), &sz
			, diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);
		if (ugh != NULL)
		{
			/* ttodata didn't like PSK data */
			ugh = builddiag("PSK data malformed (%s): %s", ugh, tok);
		}
		else
		{
			chunk_t secret = { buf, sz };
			*psk = chunk_clone(secret);
			(void) shift();
		}
	}
	return ugh;
}

typedef enum rsa_private_key_part_t rsa_private_key_part_t;

enum rsa_private_key_part_t {
	RSA_PART_MODULUS          = 0,
	RSA_PART_PUBLIC_EXPONENT  = 1,
	RSA_PART_PRIVATE_EXPONENT = 2,
	RSA_PART_PRIME1           = 3,
	RSA_PART_PRIME2           = 4,
	RSA_PART_EXPONENT1        = 5,
	RSA_PART_EXPONENT2        = 6,
	RSA_PART_COEFFICIENT      = 7
};

const char *rsa_private_key_part_names[] = {
	"Modulus",
	"PublicExponent",
	"PrivateExponent",
	"Prime1",
	"Prime2",
	"Exponent1",
	"Exponent2",
	"Coefficient"
};

/**
 * Parse fields of an RSA private key in BIND 8.2's representation
 * consistiong of a braced list of keyword and value pairs in required order.
 */
static err_t process_rsa_secret(private_key_t **key)
{
	chunk_t rsa_chunk[countof(rsa_private_key_part_names)];
	u_char buf[RSA_MAX_ENCODING_BYTES];   /* limit on size of binary representation of key */
	rsa_private_key_part_t part, p;
	size_t sz;
	err_t ugh;

	for (part = RSA_PART_MODULUS; part <= RSA_PART_COEFFICIENT; part++)
	{
		const char *keyword = rsa_private_key_part_names[part];

		if (!shift())
		{
			ugh = "premature end of RSA key";
			goto end;
		}
		if (!tokeqword(keyword))
		{
			ugh = builddiag("%s keyword not found where expected in RSA key"
				, keyword);
			goto end;
		}
		if (!(shift() && (!tokeq(":") || shift())))   /* ignore optional ":" */
		{
			ugh = "premature end of RSA key";
			goto end;
		}
		ugh = ttodatav(tok, flp->cur - tok, 0, buf, sizeof(buf), &sz,
					   diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);
		if (ugh)
		{
			ugh = builddiag("RSA data malformed (%s): %s", ugh, tok);
			goto end;
		}
		rsa_chunk[part] = chunk_create(buf, sz);
		rsa_chunk[part] = chunk_clone(rsa_chunk[part]);
	}

	/* We require an (indented) '}' and the end of the record.
	 * We break down the test so that the diagnostic will be more helpful.
	 * Some people don't seem to wish to indent the brace!
	 */
	if (!shift() || !tokeq("}"))
	{
		ugh = "malformed end of RSA private key -- indented '}' required";
		goto end;
	}
	if (shift())
	{
		ugh = "malformed end of RSA private key -- unexpected token after '}'";
		goto end;
	}

	*key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					BUILD_RSA_MODULUS,  rsa_chunk[RSA_PART_MODULUS],
					BUILD_RSA_PUB_EXP,  rsa_chunk[RSA_PART_PUBLIC_EXPONENT],
					BUILD_RSA_PRIV_EXP, rsa_chunk[RSA_PART_PRIVATE_EXPONENT],
					BUILD_RSA_PRIME1,   rsa_chunk[RSA_PART_PRIME1],
					BUILD_RSA_PRIME2,   rsa_chunk[RSA_PART_PRIME2],
					BUILD_RSA_EXP1,     rsa_chunk[RSA_PART_EXPONENT1],
					BUILD_RSA_EXP2,     rsa_chunk[RSA_PART_EXPONENT2],
					BUILD_RSA_COEFF,    rsa_chunk[RSA_PART_COEFFICIENT],
					BUILD_END);

	if (*key == NULL)
	{
		ugh = "parsing of RSA private key failed";
	}

end:
	/* clean up and return */
	for (p = RSA_PART_MODULUS ; p < part; p++)
	{
		chunk_clear(&rsa_chunk[p]);
	}
	return ugh;
}

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
typedef struct {
	char secret[PROMPT_PASS_LEN+1];
	bool prompt;
	int fd;
	int try;
} prompt_pass_t;

/**
 * Passphrase callback to read from whack fd
 */
static shared_key_t* whack_pass_cb(prompt_pass_t *pass, shared_key_type_t type,
								identification_t *me, identification_t *other,
								id_match_t *match_me, id_match_t *match_other)
{
	int n;

	if (type != SHARED_ANY && type != SHARED_PRIVATE_KEY_PASS)
	{
		return NULL;
	}

	if (pass->try > MAX_PROMPT_PASS_TRIALS)
	{
		whack_log(RC_LOG_SERIOUS, "invalid passphrase, too many trials");
		return NULL;
	}
	if (pass->try == 1)
	{
		whack_log(RC_ENTERSECRET, "need passphrase for 'private key'");
	}
	else
	{
		whack_log(RC_ENTERSECRET, "invalid passphrase, please try again");
	}
	pass->try++;

	n = read(pass->fd, pass->secret, PROMPT_PASS_LEN);
	if (n == -1)
	{
		whack_log(RC_LOG_SERIOUS, "read(whackfd) failed");
		return NULL;
	}
	pass->secret[n-1] = '\0';

	if (strlen(pass->secret) == 0)
	{
		whack_log(RC_LOG_SERIOUS, "no passphrase entered, aborted");
		return NULL;
	}
	if (match_me)
	{
		*match_me = ID_MATCH_PERFECT;
	}
	if (match_other)
	{
		*match_other = ID_MATCH_NONE;
	}
	return shared_key_create(SHARED_PRIVATE_KEY_PASS,
				chunk_clone(chunk_create(pass->secret, strlen(pass->secret))));
}

/**
 *  Loads a PKCS#1 or PGP private key file
 */
static private_key_t* load_private_key(char* filename, prompt_pass_t *pass,
									   key_type_t type)
{
	private_key_t *key = NULL;
	char *path;

	path = concatenate_paths(PRIVATE_KEY_PATH, filename);
	if (pass && pass->prompt && pass->fd != NULL_FD)
	{	/* use passphrase callback */
		callback_cred_t *cb;

		cb = callback_cred_create_shared((void*)whack_pass_cb, pass);
		lib->credmgr->add_local_set(lib->credmgr, &cb->set);

		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path, BUILD_END);
		lib->credmgr->remove_local_set(lib->credmgr, &cb->set);
		cb->destroy(cb);
		if (key)
		{
			whack_log(RC_SUCCESS, "valid passphrase");
		}
	}
	else if (pass)
	{	/* use a given passphrase */
		mem_cred_t *mem;
		shared_key_t *shared;

		mem = mem_cred_create();
		lib->credmgr->add_local_set(lib->credmgr, &mem->set);
		shared = shared_key_create(SHARED_PRIVATE_KEY_PASS,
				chunk_clone(chunk_create(pass->secret, strlen(pass->secret))));
		mem->add_shared(mem, shared, NULL);
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path, BUILD_END);
		lib->credmgr->remove_local_set(lib->credmgr, &mem->set);
		mem->destroy(mem);
	}
	else
	{	/* no passphrase */
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_FROM_FILE, path, BUILD_END);

	}
	if (key)
	{
		plog("  loaded private key from '%s'", filename);
	}
	else
	{
		plog("  syntax error in private key file");
	}
	return key;
}

/**
 * process a key file protected with optional passphrase which can either be
 * read from ipsec.secrets or prompted for by using whack
 */
static err_t process_keyfile(private_key_t **key, key_type_t type, int whackfd)
{
	char filename[BUF_LEN];
	prompt_pass_t pass;

	memset(filename,'\0', BUF_LEN);
	memset(pass.secret,'\0', sizeof(pass.secret));
	pass.prompt = FALSE;
	pass.fd = whackfd;
	pass.try = 1;

	/* we expect the filename of a PKCS#1 private key file */

	if (*tok == '"' || *tok == '\'')  /* quoted filename */
		memcpy(filename, tok+1, flp->cur - tok - 2);
	else
		memcpy(filename, tok, flp->cur - tok);

	if (shift())
	{
		/* we expect an appended passphrase or passphrase prompt*/
		if (tokeqword("%prompt"))
		{
			if (pass.fd == NULL_FD)
			{
				return "Private key file -- enter passphrase using 'ipsec secrets'";
			}
			pass.prompt = TRUE;
		}
		else
		{
			char *passphrase = tok;
			size_t len = flp->cur - passphrase;

			if (*tok == '"' || *tok == '\'')  /* quoted passphrase */
			{
				passphrase++;
				len -= 2;
			}
			if (len > PROMPT_PASS_LEN)
			{
				return "Private key file -- passphrase exceeds 64 characters";
			}
			memcpy(pass.secret, passphrase, len);
		}
		if (shift())
		{
			return "Private key file -- unexpected token after passphrase";
		}
	}
	*key = load_private_key(filename, &pass, type);

	return *key ? NULL : "Private key file -- could not be loaded";
}

/**
 * Process pin read from ipsec.secrets or prompted for it using whack
 */
static err_t process_pin(secret_t *s, int whackfd)
{
	smartcard_t *sc;
	const char *pin_status = "no pin";

	s->kind = SECRET_PIN;

	/* looking for the smartcard keyword */
	if (!shift() || strncmp(tok, SCX_TOKEN, strlen(SCX_TOKEN)) != 0)
		 return "PIN keyword must be followed by %smartcard<reader>:<id>";

	sc = scx_add(scx_parse_number_slot_id(tok + strlen(SCX_TOKEN)));
	s->u.smartcard = sc;
	scx_share(sc);
	if (sc->pin.ptr != NULL)
	{
		scx_release_context(sc);
		scx_free_pin(&sc->pin);
	}
	sc->valid = FALSE;

	if (!shift())
		return "PIN statement must be terminated either by <pin code>, %pinpad or %prompt";

	if (tokeqword("%prompt"))
	{
		shift();
		/* if whackfd exists, whack will be used to prompt for a pin */
		if (whackfd != NULL_FD)
			pin_status = scx_get_pin(sc, whackfd) ? "valid pin" : "invalid pin";
		else
			pin_status = "pin entry via prompt";
	}
	else if (tokeqword("%pinpad"))
	{
		chunk_t empty_pin = { "", 0 };

		shift();

		/* pin will be entered via pin pad during verification */
		sc->pin = chunk_clone(empty_pin);
		sc->pinpad = TRUE;
		sc->valid = TRUE;
		pin_status = "pin entry via pad";
		if (pkcs11_keep_state)
		{
			scx_verify_pin(sc);
		}
	}
	else
	{
		/* we read the pin directly from ipsec.secrets */
		err_t ugh = process_psk_secret(&sc->pin);
		if (ugh != NULL)
		return ugh;
		/* verify the pin */
		pin_status = scx_verify_pin(sc) ? "valid PIN" : "invalid PIN";
	}
#ifdef SMARTCARD
	{
		char buf[BUF_LEN];

		if (sc->any_slot)
			snprintf(buf, BUF_LEN, "any slot");
		else
			snprintf(buf, BUF_LEN, "slot: %lu", sc->slot);

		plog("  %s for #%d (%s, id: %s)"
			, pin_status, sc->number, scx_print_slot(sc, ""), sc->id);
	}
#else
	plog("  warning: SMARTCARD support is deactivated in pluto/Makefile!");
#endif
	return NULL;
}

static void log_psk(char *label, secret_t *s)
{
	int n = 0;
	char buf[BUF_LEN];
	enumerator_t *enumerator;
	identification_t *id;

	if (s->ids->get_count(s->ids) == 0)
	{
		n = snprintf(buf, BUF_LEN, "%%any");
	}
	else
	{
		enumerator = s->ids->create_enumerator(s->ids);
		while(enumerator->enumerate(enumerator, &id))
		{
			n += snprintf(buf + n, BUF_LEN - n, "%Y ", id);
			if (n >= BUF_LEN)
			{
				n = BUF_LEN - 1;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	plog("  loaded %s secret for %.*s", label, n, buf);
}

static void process_secret(secret_t *s, int whackfd)
{
	err_t ugh = NULL;

	s->kind = SECRET_PSK;  /* default */
	if (tokeqword("psk"))
	{
		log_psk("PSK", s);

		/* preshared key: quoted string or ttodata format */
		ugh = !shift()? "unexpected end of record in PSK"
			: process_psk_secret(&s->u.preshared_secret);
	}
	else if (tokeqword("xauth"))
	{
		s->kind = SECRET_XAUTH;
		log_psk("XAUTH", s);

		/* xauth secret: quoted string or ttodata format */
		ugh = !shift()? "unexpected end of record in XAUTH"
			: process_psk_secret(&s->u.preshared_secret);
	}
	else if (tokeqword("rsa"))
	{
		/* RSA key: the fun begins.
		 * A braced list of keyword and value pairs.
		 */
		s->kind = SECRET_PUBKEY;
		if (!shift())
		{
			ugh = "bad RSA key syntax";
		}
		else if (tokeq("{"))
		{
			ugh = process_rsa_secret(&s->u.private_key);
		}
		else
		{
		   ugh = process_keyfile(&s->u.private_key, KEY_RSA, whackfd);
		}
	}
	else if (tokeqword("ecdsa"))
	{
		s->kind = SECRET_PUBKEY;
		if (!shift())
		{
			ugh = "bad ECDSA key syntax";
		}
		else
		{
		   ugh = process_keyfile(&s->u.private_key, KEY_ECDSA, whackfd);
		}
	}
	else if (tokeqword("pin"))
	{
		ugh = process_pin(s, whackfd);
	}
	else
	{
		ugh = builddiag("unrecognized key format: %s", tok);
	}

	if (ugh != NULL)
	{
		loglog(RC_LOG_SERIOUS, "\"%s\" line %d: %s"
			, flp->filename, flp->lino, ugh);
		s->ids->destroy_offset(s->ids, offsetof(identification_t, destroy));
		free(s);
	}
	else if (flushline("expected record boundary in key"))
	{
		/* gauntlet has been run: install new secret */
		lock_certs_and_keys("process_secret");
		s->next = secrets;
		secrets = s;
		unlock_certs_and_keys("process_secrets");
	}
}

static void process_secrets_file(const char *file_pat, int whackfd);    /* forward declaration */

static void process_secret_records(int whackfd)
{
	/* read records from ipsec.secrets and load them into our table */
	for (;;)
	{
		(void)flushline(NULL);  /* silently ditch leftovers, if any */
		if (flp->bdry == B_file)
		{
			break;
		}
		flp->bdry = B_none;     /* eat the Record Boundary */
		(void)shift();  /* get real first token */

		if (tokeqword("include"))
		{
			/* an include directive */
			char fn[MAX_TOK_LEN];       /* space for filename (I hope) */
			char *p = fn;
			char *end_prefix = strrchr(flp->filename, '/');

			if (!shift())
			{
				loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of include directive"
					, flp->filename, flp->lino);
				continue;   /* abandon this record */
			}

			/* if path is relative and including file's pathname has
			 * a non-empty dirname, prefix this path with that dirname.
			 */
			if (tok[0] != '/' && end_prefix != NULL)
			{
				size_t pl = end_prefix - flp->filename + 1;

				/* "clamp" length to prevent problems now;
				 * will be rediscovered and reported later.
				 */
				if (pl > sizeof(fn))
				{
					pl = sizeof(fn);
				}
				memcpy(fn, flp->filename, pl);
				p += pl;
			}
			if (flp->cur - tok >= &fn[sizeof(fn)] - p)
			{
				loglog(RC_LOG_SERIOUS, "\"%s\" line %d: include pathname too long"
					, flp->filename, flp->lino);
				continue;   /* abandon this record */
			}
			strcpy(p, tok);
			(void) shift();     /* move to Record Boundary, we hope */
			if (flushline("ignoring malformed INCLUDE -- expected Record Boundary after filename"))
			{
				process_secrets_file(fn, whackfd);
				tok = NULL;     /* correct, but probably redundant */
			}
		}
		else
		{
			/* expecting a list of indices and then the key info */
			secret_t *s = malloc_thing(secret_t);

			zero(s);
			s->ids = linked_list_create();
			s->kind = SECRET_PSK;  /* default */
			s->u.preshared_secret = chunk_empty;
			s->next = NULL;

			for (;;)
			{
				if (tokeq(":"))
				{
					/* found key part */
					shift();    /* discard explicit separator */
					process_secret(s, whackfd);
					break;
				}
				else
				{
					identification_t *id;

					id = identification_create_from_string(tok);
					s->ids->insert_last(s->ids, id);

					if (!shift())
					{
						/* unexpected Record Boundary or EOF */
						loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end"
							   " of id list", flp->filename, flp->lino);
						s->ids->destroy_offset(s->ids,
										offsetof(identification_t, destroy));
						free(s);
						break;
					}
				}
			}
		}
	}
}

static int globugh(const char *epath, int eerrno)
{
	log_errno_routine(eerrno, "problem with secrets file \"%s\"", epath);
	return 1;   /* stop glob */
}

static void process_secrets_file(const char *file_pat, int whackfd)
{
	struct file_lex_position pos;
	char **fnp;

	pos.depth = flp == NULL? 0 : flp->depth + 1;

	if (pos.depth > 10)
	{
		loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
		return;
	}

#ifdef HAVE_GLOB_H
	/* do globbing */
	{
		glob_t globbuf;
		int r = glob(file_pat, GLOB_ERR, globugh, &globbuf);

		if (r != 0)
		{
			switch (r)
			{
			case GLOB_NOSPACE:
				loglog(RC_LOG_SERIOUS, "out of space processing secrets filename \"%s\"", file_pat);
				break;
			case GLOB_ABORTED:
				break;  /* already logged */
			case GLOB_NOMATCH:
				loglog(RC_LOG_SERIOUS, "no secrets filename matched \"%s\"", file_pat);
				break;
			default:
				loglog(RC_LOG_SERIOUS, "unknown glob error %d", r);
				break;
			}
			globfree(&globbuf);
			return;
		}

		/* for each file... */
		for (fnp = globbuf.gl_pathv; *fnp != NULL; fnp++)
		{
			if (lexopen(&pos, *fnp, FALSE))
			{
				plog("loading secrets from \"%s\"", *fnp);
				flushline("file starts with indentation (continuation notation)");
				process_secret_records(whackfd);
				lexclose();
			}
		}

		globfree(&globbuf);
	}
#else /* HAVE_GLOB_H */
	/* if glob(3) is not available, try to load pattern directly */
	if (lexopen(&pos, file_pat, FALSE))
	{
		plog("loading secrets from \"%s\"", file_pat);
		flushline("file starts with indentation (continuation notation)");
		process_secret_records(whackfd);
		lexclose();
	}
#endif /* HAVE_GLOB_H */
}

void free_preshared_secrets(void)
{
	lock_certs_and_keys("free_preshared_secrets");

	if (secrets != NULL)
	{
		secret_t *s, *ns;

		plog("forgetting secrets");

		for (s = secrets; s != NULL; s = ns)
		{
			ns = s->next;
			s->ids->destroy_offset(s->ids, offsetof(identification_t, destroy));

			switch (s->kind)
			{
				case SECRET_PSK:
				case SECRET_XAUTH:
					free(s->u.preshared_secret.ptr);
					break;
				case SECRET_PUBKEY:
					DESTROY_IF(s->u.private_key);
					break;
				case SECRET_PIN:
					scx_release(s->u.smartcard);
					break;
				default:
					bad_case(s->kind);
			}
			free(s);
		}
		secrets = NULL;
	}

	unlock_certs_and_keys("free_preshard_secrets");
}

void load_preshared_secrets(int whackfd)
{
	free_preshared_secrets();
	(void) process_secrets_file(shared_secrets_file, whackfd);
}

/* public key machinery
 * Note: caller must set dns_auth_level.
 */

pubkey_t* public_key_from_rsa(public_key_t *key)
{
	pubkey_t *p = malloc_thing(pubkey_t);

	zero(p);
	p->id = identification_create_from_string("%any");  /* don't know, doesn't matter */
	p->issuer = NULL;
	p->serial = chunk_empty;
	p->public_key = key;

	/* note that we return a 1 reference count upon creation:
	 * invariant: recount > 0.
	 */
	p->refcnt = 1;
	return p;
}

/* Free a public key record.
 * As a convenience, this returns a pointer to next.
 */
pubkey_list_t* free_public_keyentry(pubkey_list_t *p)
{
	pubkey_list_t *nxt = p->next;

	if (p->key != NULL)
	{
		unreference_key(&p->key);
	}
	free(p);
	return nxt;
}

void free_public_keys(pubkey_list_t **keys)
{
	while (*keys != NULL)
	{
		*keys = free_public_keyentry(*keys);
	}
}

/* root of chained public key list */

pubkey_list_t *pubkeys = NULL;  /* keys from ipsec.conf */

void free_remembered_public_keys(void)
{
	free_public_keys(&pubkeys);
}

/**
 * Transfer public keys from *keys list to front of pubkeys list
 */
void transfer_to_public_keys(struct gw_info *gateways_from_dns
#ifdef USE_KEYRR
, pubkey_list_t **keys
#endif /* USE_KEYRR */
)
{
	{
		struct gw_info *gwp;

		for (gwp = gateways_from_dns; gwp != NULL; gwp = gwp->next)
		{
			pubkey_list_t *pl = malloc_thing(pubkey_list_t);

			pl->key = gwp->key; /* note: this is a transfer */
			gwp->key = NULL;    /* really, it is! */
			pl->next = pubkeys;
			pubkeys = pl;
		}
	}

#ifdef USE_KEYRR
	{
		pubkey_list_t **pp = keys;

		while (*pp != NULL)
		{
			pp = &(*pp)->next;
		}
		*pp = pubkeys;
		pubkeys = *keys;
		*keys = NULL;
	}
#endif /* USE_KEYRR */
}


static void install_public_key(pubkey_t *pk, pubkey_list_t **head)
{
	pubkey_list_t *p = malloc_thing(pubkey_list_t);

	/* install new key at front */
	p->key = reference_key(pk);
	p->next = *head;
	*head = p;
}

void delete_public_keys(identification_t *id, key_type_t type,
						identification_t *issuer, chunk_t serial)
{
	pubkey_list_t **pp, *p;
	pubkey_t *pk;
	key_type_t pk_type;

	for (pp = &pubkeys; (p = *pp) != NULL; )
	{
		pk = p->key;
		pk_type = pk->public_key->get_type(pk->public_key);

		if (id->equals(id, pk->id) && pk_type == type
		&& (issuer == NULL || pk->issuer == NULL
			|| issuer->equals(issuer, pk->issuer))
		&& (serial.ptr == NULL || chunk_equals(serial, pk->serial)))
		{
			*pp = free_public_keyentry(p);
		}
		else
		{
			pp = &p->next;
		}
	}
}

pubkey_t* reference_key(pubkey_t *pk)
{
	DBG(DBG_CONTROLMORE,
		DBG_log("  ref key: %p %p cnt %d '%Y'",
				 pk, pk->public_key, pk->refcnt, pk->id)
	)
	pk->refcnt++;
	return pk;
}

void unreference_key(pubkey_t **pkp)
{
	pubkey_t *pk = *pkp;

	if (pk == NULL)
	{
		return;
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("unref key: %p %p cnt %d '%Y'",
				 pk, pk->public_key, pk->refcnt, pk->id)
	)

	/* cancel out the pointer */
	*pkp = NULL;

	passert(pk->refcnt != 0);
	pk->refcnt--;
	if (pk->refcnt == 0)
	{
		free_public_key(pk);
	}
}

bool add_public_key(identification_t *id, enum dns_auth_level dns_auth_level,
					enum pubkey_alg alg, chunk_t rfc3110_key,
					pubkey_list_t **head)
{
	public_key_t *key = NULL;
	pubkey_t *pk;

   /* first: algorithm-specific decoding of key chunk */
	switch (alg)
	{
		case PUBKEY_ALG_RSA:
			key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
										BUILD_BLOB_DNSKEY, rfc3110_key,
										BUILD_END);
			if (key == NULL)
			{
				return FALSE;
			}
			break;
		default:
			bad_case(alg);
	}

	pk = malloc_thing(pubkey_t);
	zero(pk);
	pk->public_key = key;
	pk->id = id->clone(id);
	pk->dns_auth_level = dns_auth_level;
	pk->until_time = UNDEFINED_TIME;
	pk->issuer = NULL;
	pk->serial = chunk_empty;
	install_public_key(pk, head);
	return TRUE;
}

/**
 * Extract id and public key a certificate and insert it into a pubkeyrec
 */
void add_public_key_from_cert(cert_t *cert , time_t until,
							  enum dns_auth_level dns_auth_level)
{
	certificate_t *certificate = cert->cert;
	identification_t *subject = certificate->get_subject(certificate);
	identification_t *issuer = NULL;
	identification_t *id;
	chunk_t serialNumber = chunk_empty;
	pubkey_t *pk;
	key_type_t pk_type;

	/* ID type: ID_DER_ASN1_DN  (X.509 subject field) */
	pk = malloc_thing(pubkey_t);
	zero(pk);
	pk->public_key = certificate->get_public_key(certificate);
	pk_type = pk->public_key->get_type(pk->public_key);
	pk->id = subject->clone(subject);
	pk->dns_auth_level = dns_auth_level;
	pk->until_time = until;
	if (certificate->get_type(certificate) == CERT_X509)
	{
		x509_t *x509 = (x509_t*)certificate;

		issuer = certificate->get_issuer(certificate);
		serialNumber = x509->get_serial(x509);
		pk->issuer = issuer->clone(issuer);
		pk->serial = chunk_clone(serialNumber);
	}
	delete_public_keys(pk->id, pk_type, pk->issuer, pk->serial);
	install_public_key(pk, &pubkeys);

	if (certificate->get_type(certificate) == CERT_X509)
	{
		x509_t *x509 = (x509_t*)certificate;
		enumerator_t *enumerator;

		/* insert all subjectAltNames from X.509 certificates */
		enumerator = x509->create_subjectAltName_enumerator(x509);
		while (enumerator->enumerate(enumerator, &id))
		{
			if (id->get_type(id) != ID_ANY)
			{
				pk = malloc_thing(pubkey_t);
				zero(pk);
				pk->id = id->clone(id);
				pk->public_key = certificate->get_public_key(certificate);
				pk->dns_auth_level = dns_auth_level;
				pk->until_time = until;
				pk->issuer = issuer->clone(issuer);
				pk->serial = chunk_clone(serialNumber);
				delete_public_keys(pk->id, pk_type, pk->issuer, pk->serial);
				install_public_key(pk, &pubkeys);
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		pgp_certificate_t *pgp_cert = (pgp_certificate_t*)certificate;
		chunk_t fingerprint = pgp_cert->get_fingerprint(pgp_cert);

		/* add v3 or v4 PGP fingerprint */
		pk = malloc_thing(pubkey_t);
		zero(pk);
		pk->id = identification_create_from_encoding(ID_KEY_ID, fingerprint);
		pk->public_key = certificate->get_public_key(certificate);
		pk->dns_auth_level = dns_auth_level;
		pk->until_time = until;
		delete_public_keys(pk->id, pk_type, pk->issuer, pk->serial);
		install_public_key(pk, &pubkeys);
	}
}

/*  when a X.509 certificate gets revoked, all instances of
 *  the corresponding public key must be removed
 */
void remove_x509_public_key(const cert_t *cert)
{
	public_key_t *revoked_key = cert->cert->get_public_key(cert->cert);
	pubkey_list_t *p, **pp;

	p  = pubkeys;
	pp = &pubkeys;

	while(p != NULL)
	{
		if (revoked_key->equals(revoked_key, p->key->public_key))
		{
			/* remove p from list and free memory */
			*pp = free_public_keyentry(p);
			loglog(RC_LOG_SERIOUS, "invalid public key deleted");
		}
		else
		{
			pp = &p->next;
		}
		p =*pp;
	}
	revoked_key->destroy(revoked_key);
}

/*
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc)
{
	pubkey_list_t *p = pubkeys;
	chunk_t serial;

	if (p != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of Public Keys:");
	}

	while (p != NULL)
	{
		pubkey_t *key = p->key;
		public_key_t *public = key->public_key;
		chunk_t keyid;

		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "  identity: '%Y'", key->id);
		whack_log(RC_COMMENT, "  pubkey:    %N %4d bits, until %T %s",
			key_type_names, public->get_type(public),
			public->get_keysize(public),
			&key->until_time, utc,
			check_expiry(key->until_time, PUBKEY_WARNING_INTERVAL, TRUE));
		if (public->get_fingerprint(public, KEYID_PUBKEY_INFO_SHA1, &keyid))
		{
			whack_log(RC_COMMENT,"  keyid:     %#B", &keyid);
		}
		if (key->issuer)
		{
			whack_log(RC_COMMENT,"  issuer:   \"%Y\"", key->issuer);
		}
		if (key->serial.len)
		{
			serial = chunk_skip_zero(key->serial);
			whack_log(RC_COMMENT,"  serial:    %#B", &serial);
		}
		p = p->next;
	}
}
