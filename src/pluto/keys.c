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

#include <glob.h>
#ifndef GLOB_ABORTED
# define GLOB_ABORTED    GLOB_ABEND     /* fix for old versions */
#endif

#include <freeswan.h>

#include <library.h>
#include <asn1/asn1.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgpcert.h"
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
#include "xauth.h"

const char *shared_secrets_file = SHARED_SECRETS_FILE;

typedef struct id_list id_list_t;

struct id_list {
	struct id id;
	id_list_t *next;
};

typedef struct secret secret_t;

struct secret {
	id_list_t *ids;
	enum PrivateKeyKind kind;
	union {
		chunk_t        preshared_secret;
		xauth_t        xauth_secret;
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

/* find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static const secret_t* get_secret(const connection_t *c,
								  enum PrivateKeyKind kind, bool asym)
{
	enum {      /* bits */
		match_default = 0x01,
		match_him     = 0x02,
		match_me      = 0x04
	};

	unsigned int best_match = 0;
	secret_t *best = NULL;
	secret_t *s;
	const struct id *my_id  = &c->spd.this.id
				  , *his_id = &c->spd.that.id;
	struct id rw_id;

	/* is there a certificate assigned to this connection? */
	if (kind == PPK_PUBKEY && c->spd.this.cert.type != CERT_NONE)
	{
		public_key_t *pub_key = cert_get_public_key(c->spd.this.cert);

		for (s = secrets; s != NULL; s = s->next)
		{
			if (s->kind == kind &&
				s->u.private_key->belongs_to(s->u.private_key, pub_key))
			{
				best = s;
				break; /* we have found the private key - no sense in searching further */
			}
		}
		pub_key->destroy(pub_key);
		return best;
	}

	if (his_id_was_instantiated(c))
	{
		/* roadwarrior: replace him with 0.0.0.0 */
		rw_id.kind = c->spd.that.id.kind;
		rw_id.name = chunk_empty;
		happy(anyaddr(addrtypeof(&c->spd.that.host_addr), &rw_id.ip_addr));
		his_id = &rw_id;
	}
	else if (kind == PPK_PSK
	&& (c->policy & (POLICY_PSK | POLICY_XAUTH_PSK))
	&& ((c->kind == CK_TEMPLATE && c->spd.that.id.kind == ID_ANY) ||
		(c->kind == CK_INSTANCE && id_is_ipaddr(&c->spd.that.id))))
	{
		/* roadwarrior: replace him with 0.0.0.0 */
		rw_id.kind = ID_IPV4_ADDR;
		happy(anyaddr(addrtypeof(&c->spd.that.host_addr), &rw_id.ip_addr));
		his_id = &rw_id;
	}

	for (s = secrets; s != NULL; s = s->next)
	{
		if (s->kind == kind)
		{
			unsigned int match = 0;

			if (s->ids == NULL)
			{
				/* a default (signified by lack of ids):
				 * accept if no more specific match found
				 */
				match = match_default;
			}
			else
			{
				/* check if both ends match ids */
				id_list_t *i;

				for (i = s->ids; i != NULL; i = i->next)
				{
					if (same_id(my_id, &i->id))
					{
						match |= match_me;
					}
					if (same_id(his_id, &i->id))
					{
						match |= match_him;
					}
				}

				/* If our end matched the only id in the list,
				 * default to matching any peer.
				 * A more specific match will trump this.
				 */
				if (match == match_me && s->ids->next == NULL)
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
				if (!asym)
				{
					break;
				}
				/* FALLTHROUGH */
			case match_default: /* default all */
			case match_me | match_default:      /* default peer */
			case match_me | match_him:  /* explicit */
				if (match == best_match)
				{
					/* two good matches are equally good:
					 * do they agree?
					 */
					bool same = FALSE;

					switch (kind)
					{
					case PPK_PSK:
						same = s->u.preshared_secret.len == best->u.preshared_secret.len
								&& memeq(s->u.preshared_secret.ptr, best->u.preshared_secret.ptr, s->u.preshared_secret.len);
						break;
					case PPK_PUBKEY:
						same = s->u.private_key->equals(s->u.private_key, best->u.private_key);
						break;
					default:
						bad_case(kind);
					}
					if (!same)
					{
						loglog(RC_LOG_SERIOUS, "multiple ipsec.secrets entries with distinct secrets match endpoints:"
							" first secret used");
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
	}
	return best;
}

/* find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 */
const chunk_t* get_preshared_secret(const connection_t *c)
{
	const secret_t *s = get_secret(c, PPK_PSK, FALSE);

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
bool has_private_key(cert_t cert)
{
	secret_t *s;
	bool has_key = FALSE;
	public_key_t *pub_key = cert_get_public_key(cert);

	for (s = secrets; s != NULL; s = s->next)
	{
		if (s->kind == PPK_PUBKEY &&
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
private_key_t* get_x509_private_key(const x509cert_t *cert)
{
	public_key_t *public_key = cert->cert->get_public_key(cert->cert);
	private_key_t *private_key = NULL;
	secret_t *s;

	for (s = secrets; s != NULL; s = s->next)
	{

		if (s->kind == PPK_PUBKEY &&
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
	const secret_t *s = get_secret(c, PPK_PUBKEY, TRUE);

	return s == NULL? NULL : s->u.private_key;
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
			part++;
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
 * Process xauth secret read from ipsec.secrets
 */
static err_t process_xauth(secret_t *s)
{
	chunk_t user_name;

	s->kind = PPK_XAUTH;

	if (!shift())
		return "missing xauth user name";
	if (*tok == '"' || *tok == '\'')  /* quoted user name */
	{
		user_name.ptr = tok + 1;
		user_name.len = flp->cur - tok - 2;
	}
	else
	{
		user_name.ptr = tok;
		user_name.len = flp->cur - tok;
	}
	plog("  loaded xauth credentials of user '%.*s'"
				, user_name.len
				, user_name.ptr);
	s->u.xauth_secret.user_name = chunk_clone(user_name);

	if (!shift())
		return "missing xauth user password";
	return process_psk_secret(&s->u.xauth_secret.user_password);
}

/**
 * Get XAUTH secret from chained secrets lists
 * only one entry is currently supported
 */
static bool xauth_get_secret(xauth_t *xauth_secret)
{
	secret_t *s;
	bool found = FALSE;

	for (s = secrets; s != NULL; s = s->next)
	{
		if (s->kind == PPK_XAUTH)
		{
			if (found)
			{
				plog("found multiple xauth secrets - first selected");
			}
			else
			{
				found = TRUE;
				*xauth_secret = s->u.xauth_secret;
			}
		}
	}
	return found;
}

/**
 * find a matching secret
 */
static bool xauth_verify_secret(const xauth_peer_t *peer,
								const xauth_t *xauth_secret)
{
	bool found = FALSE;
	secret_t *s;

	for (s = secrets; s != NULL; s = s->next)
	{
		if (s->kind == PPK_XAUTH)
		{
			if (!chunk_equals(xauth_secret->user_name, s->u.xauth_secret.user_name))
			{
				continue;
			}
			found = TRUE;
			if (chunk_equals(xauth_secret->user_password, s->u.xauth_secret.user_password))
			{
				return TRUE;
			}
		}
	}
	plog("xauth user '%.*s' %s"
	   , xauth_secret->user_name.len, xauth_secret->user_name.ptr
	   , found? "sent wrong password":"not found");
	return FALSE;
}

/**
 * the global xauth_module struct is defined here
 */
xauth_module_t xauth_module;

/**
 * Assign the default xauth functions to any null function pointers
 */
void xauth_defaults(void)
{
	if (xauth_module.get_secret == NULL)
	{
		DBG(DBG_CONTROL,
			DBG_log("xauth module: using default get_secret() function")
		)
		xauth_module.get_secret = xauth_get_secret;
	}
	if (xauth_module.verify_secret == NULL)
	{
		DBG(DBG_CONTROL,
			DBG_log("xauth module: using default verify_secret() function")
		)
		xauth_module.verify_secret = xauth_verify_secret;
	}
};

/**
 * Process pin read from ipsec.secrets or prompted for it using whack
 */
static err_t process_pin(secret_t *s, int whackfd)
{
	smartcard_t *sc;
	const char *pin_status = "no pin";

	s->kind = PPK_PIN;

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

static void log_psk(secret_t *s)
{
	int n = 0;
	char buf[BUF_LEN];
	id_list_t *id_list = s->ids;

	if (id_list == NULL)
	{
		n = snprintf(buf, BUF_LEN, "%%any");
	}
	else
	{
		do
		{
			n += idtoa(&id_list->id, buf + n, BUF_LEN - n);
			if (n >= BUF_LEN)
			{
				n = BUF_LEN - 1;
				break;
			}
			else if (n < BUF_LEN - 1)
			{
				n += snprintf(buf + n, BUF_LEN - n, " ");
			}
			id_list = id_list->next;
		}
		while (id_list);
	}
	plog("  loaded shared key for %.*s", n, buf);
}

static void process_secret(secret_t *s, int whackfd)
{
	err_t ugh = NULL;

	s->kind = PPK_PSK;  /* default */
	if (*tok == '"' || *tok == '\'')
	{
		/* old PSK format: just a string */
		log_psk(s);
		ugh = process_psk_secret(&s->u.preshared_secret);
	}
	else if (tokeqword("psk"))
	{
		/* preshared key: quoted string or ttodata format */
		log_psk(s);
		ugh = !shift()? "unexpected end of record in PSK"
			: process_psk_secret(&s->u.preshared_secret);
	}
	else if (tokeqword("rsa"))
	{
		/* RSA key: the fun begins.
		 * A braced list of keyword and value pairs.
		 */
		s->kind = PPK_PUBKEY;
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
		s->kind = PPK_PUBKEY;
		if (!shift())
		{
			ugh = "bad ECDSA key syntax";
		}
		else
		{
		   ugh = process_keyfile(&s->u.private_key, KEY_ECDSA, whackfd);
		}
	}
	else if (tokeqword("xauth"))
	{
		ugh = process_xauth(s);
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
			s->ids = NULL;
			s->kind = PPK_PSK;  /* default */
			s->u.preshared_secret = chunk_empty;
			s->next = NULL;

			for (;;)
			{
				if (tok[0] == '"' || tok[0] == '\'')
				{
					/* found key part */
					process_secret(s, whackfd);
					break;
				}
				else if (tokeq(":"))
				{
					/* found key part */
					shift();    /* discard explicit separator */
					process_secret(s, whackfd);
					break;
				}
				else
				{
					/* an id
					 * See RFC2407 IPsec Domain of Interpretation 4.6.2
					 */
					struct id id;
					err_t ugh;

					if (tokeq("%any"))
					{
						id = empty_id;
						id.kind = ID_IPV4_ADDR;
						ugh = anyaddr(AF_INET, &id.ip_addr);
					}
					else if (tokeq("%any6"))
					{
						id = empty_id;
						id.kind = ID_IPV6_ADDR;
						ugh = anyaddr(AF_INET6, &id.ip_addr);
					}
					else
					{
						ugh = atoid(tok, &id, FALSE);
					}

					if (ugh != NULL)
					{
						loglog(RC_LOG_SERIOUS
							, "ERROR \"%s\" line %d: index \"%s\" %s"
							, flp->filename, flp->lino, tok, ugh);
					}
					else
					{
						id_list_t *i = malloc_thing(id_list_t);

						i->id = id;
						unshare_id_content(&i->id);
						i->next = s->ids;
						s->ids = i;
						/* DBG_log("id type %d: %s %.*s", i->kind, ip_str(&i->ip_addr), (int)i->name.len, i->name.ptr); */
					}
					if (!shift())
					{
						/* unexpected Record Boundary or EOF */
						loglog(RC_LOG_SERIOUS, "\"%s\" line %d: unexpected end of id list"
							, flp->filename, flp->lino);
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
	glob_t globbuf;

	pos.depth = flp == NULL? 0 : flp->depth + 1;

	if (pos.depth > 10)
	{
		loglog(RC_LOG_SERIOUS, "preshared secrets file \"%s\" nested too deeply", file_pat);
		return;
	}

	/* do globbing */
	{
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
	}

	/* for each file... */
	for (fnp = globbuf.gl_pathv; *fnp != NULL; fnp++)
	{
		if (lexopen(&pos, *fnp, FALSE))
		{
			plog("loading secrets from \"%s\"", *fnp);
			(void) flushline("file starts with indentation (continuation notation)");
			process_secret_records(whackfd);
			lexclose();
		}
	}

	globfree(&globbuf);
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
			id_list_t *i, *ni;

			ns = s->next;       /* grab before freeing s */
			for (i = s->ids; i != NULL; i = ni)
			{
				ni = i->next;   /* grab before freeing i */
				free_id_content(&i->id);
				free(i);
			}
			switch (s->kind)
			{
			case PPK_PSK:
				free(s->u.preshared_secret.ptr);
				break;
			case PPK_PUBKEY:
				DESTROY_IF(s->u.private_key);
				break;
			case PPK_XAUTH:
				free(s->u.xauth_secret.user_name.ptr);
				free(s->u.xauth_secret.user_password.ptr);
				break;
			case PPK_PIN:
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

/* extract id and public key from x.509 certificate and
 * insert it into a pubkeyrec
 */
void add_x509_public_key(x509cert_t *cert , time_t until,
						 enum dns_auth_level dns_auth_level)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	identification_t *subject = certificate->get_subject(certificate);
	identification_t *issuer = certificate->get_issuer(certificate);
	identification_t *id;
	chunk_t serialNumber = x509->get_serial(x509);
	pubkey_t *pk;
	key_type_t pk_type;
	enumerator_t *enumerator;

	/* ID type: ID_DER_ASN1_DN  (X.509 subject field) */
	pk = malloc_thing(pubkey_t);
	zero(pk);
	pk->public_key = certificate->get_public_key(certificate);
	pk->id = subject->clone(subject);
	pk->dns_auth_level = dns_auth_level;
	pk->until_time = until;
	pk->issuer = issuer->clone(issuer);
	pk->serial = chunk_clone(serialNumber);
	pk_type = pk->public_key->get_type(pk->public_key);
	delete_public_keys(pk->id, pk_type, pk->issuer, pk->serial);
	install_public_key(pk, &pubkeys);

	/* insert all subjectAltNames */
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

/* extract id and public key from OpenPGP certificate and
 * insert it into a pubkeyrec
 */
void add_pgp_public_key(pgpcert_t *cert , time_t until,
						enum dns_auth_level dns_auth_level)
{
	pubkey_t *pk;
	key_type_t pk_type;

	pk = malloc_thing(pubkey_t);
	zero(pk);
	pk->public_key = cert->public_key->get_ref(cert->public_key);
	pk->id = cert->fingerprint->clone(cert->fingerprint);
	pk->dns_auth_level = dns_auth_level;
	pk->until_time = until;
	pk_type = pk->public_key->get_type(pk->public_key);
	delete_public_keys(pk->id, pk_type, NULL, chunk_empty);
	install_public_key(pk, &pubkeys);
}

/*  when a X.509 certificate gets revoked, all instances of
 *  the corresponding public key must be removed
 */
void remove_x509_public_key(const x509cert_t *cert)
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
			public->get_keysize(public) * BITS_PER_BYTE,
			&key->until_time, utc,
			check_expiry(key->until_time, PUBKEY_WARNING_INTERVAL, TRUE));
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_INFO_SHA1, &keyid))
		{
			whack_log(RC_COMMENT,"  keyid:     %#B", &keyid);
		}
		if (key->issuer)
		{
			whack_log(RC_COMMENT,"  issuer:   \"%Y\"", key->issuer);
		}
		if (key->serial.len)
		{
			whack_log(RC_COMMENT,"  serial:    %#B", &key->serial);
		}
		p = p->next;
	}
}
