/* Support of OpenPGP certificates
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id$
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <freeswan.h>
#include <ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "mp_defs.h"
#include "log.h"
#include "id.h"
#include "pgp.h"
#include "certs.h"
#include "md5.h"
#include "whack.h"
#include "pkcs1.h"
#include "keys.h"

/*
 * chained list of OpenPGP end certificates
 */
static pgpcert_t *pgpcerts   = NULL;

/*
 * OpenPGP packet tags defined in section 4.3 of RFC 2440
 */
#define PGP_PKT_RESERVED                 0
#define PGP_PKT_PUBKEY_ENC_SESSION_KEY   1
#define PGP_PKT_SIGNATURE                2
#define PGP_PKT_SYMKEY_ENC_SESSION_KEY   3
#define PGP_PKT_ONE_PASS_SIGNATURE_PKT   4
#define PGP_PKT_SECRET_KEY               5
#define PGP_PKT_PUBLIC_KEY               6
#define PGP_PKT_SECRET_SUBKEY            7
#define PGP_PKT_COMPRESSED_DATA          8
#define PGP_PKT_SYMKEY_ENC_DATA          9
#define PGP_PKT_MARKER                  10
#define PGP_PKT_LITERAL_DATA            11
#define PGP_PKT_TRUST                   12
#define PGP_PKT_USER_ID                 13
#define PGP_PKT_PUBLIC_SUBKEY           14
#define PGP_PKT_ROOF                    15

static const char *const pgp_packet_type_name[] = {
	"Reserved",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret Key Packet",
	"Public Key Packet",
	"Secret Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public Subkey Packet"
};

/*
 * OpenPGP public key algorithms defined in section 9.1 of RFC 2440
 */
#define PGP_PUBKEY_ALG_RSA               1
#define PGP_PUBKEY_ALG_RSA_ENC_ONLY      2
#define PGP_PUBKEY_ALG_RSA_SIGN_ONLY     3
#define PGP_PUBKEY_ALG_ELGAMAL_ENC_ONLY 16
#define PGP_PUBKEY_ALG_DSA              17
#define PGP_PUBKEY_ALG_ECC              18
#define PGP_PUBKEY_ALG_ECDSA            19
#define PGP_PUBKEY_ALG_ELGAMAL          20

/*
 * OpenPGP symmetric key algorithms defined in section 9.2 of RFC 2440
  */
#define PGP_SYM_ALG_PLAIN        0
#define PGP_SYM_ALG_IDEA         1
#define PGP_SYM_ALG_3DES         2
#define PGP_SYM_ALG_CAST5        3
#define PGP_SYM_ALG_BLOWFISH     4
#define PGP_SYM_ALG_SAFER        5
#define PGP_SYM_ALG_DES          6
#define PGP_SYM_ALG_AES          7
#define PGP_SYM_ALG_AES_192      8
#define PGP_SYM_ALG_AES_256      9
#define PGP_SYM_ALG_TWOFISH     10
#define PGP_SYM_ALG_ROOF        11

static const char *const pgp_sym_alg_name[] = {
	"Plaintext",
	"IDEA",
	"3DES",
	"CAST5",
	"Blowfish",
	"SAFER",
	"DES",
	"AES",
	"AES-192",
	"AES-256",
	"Twofish"
};

/*
 * Size of PGP Key ID
 */
#define PGP_KEYID_SIZE          8

const pgpcert_t empty_pgpcert = {
	  NULL     , /* *next */
			0  , /* installed */
			0  , /* count */
	{ NULL, 0 }, /* certificate */
			0  , /* created */
			0  , /* until */
			0  , /* pubkeyAlgorithm */
	{ NULL, 0 }, /* modulus */
	{ NULL, 0 }, /* publicExponent */
	   ""        /* fingerprint */
};

static size_t
pgp_size(chunk_t *blob, int len)
{
	size_t size = 0;

	blob->len -= len;
	while (len-- > 0)
		size = 256*size + *blob->ptr++;
	return size;
}

/*
 * extracts the length of a PGP packet
 */
static size_t
pgp_old_packet_length(chunk_t *blob)
{
	/* bits 0 and 1 define the packet length type */
	int len_type = 0x03 & *blob->ptr++;

	blob->len--;

	/* len_type: 0 -> 1 byte, 1 -> 2 bytes, 2 -> 4 bytes */
	return pgp_size(blob, (len_type == 0)? 1: len_type << 1);
}

/*
 * extracts PGP packet version (V3 or V4)
 */
static u_char
pgp_version(chunk_t *blob)
{
	u_char version = *blob->ptr++;
	blob->len--;
	DBG(DBG_PARSING,
		DBG_log("L3 - version:");
		DBG_log("  V%d", version)
	)
	return version;
}

/*
 * Parse OpenPGP public key packet defined in section 5.5.2 of RFC 2440
 */
static bool
parse_pgp_pubkey_packet(chunk_t *packet, pgpcert_t *cert)
{
	u_char version = pgp_version(packet);

	if (version < 3 || version > 4)
	{
		plog("PGP packet version V%d not supported", version);
		return FALSE;
	}

	/* creation date - 4 bytes */
	cert->created = (time_t)pgp_size(packet, 4);
	DBG(DBG_PARSING,
		DBG_log("L3 - created:");
		DBG_log("  %T", &cert->created, TRUE)
	)

	if (version == 3)
	{
		/* validity in days - 2 bytes */
		cert->until   = (time_t)pgp_size(packet, 2);

		/* validity of 0 days means that the key never expires */
		if (cert->until > 0)
			cert->until = cert->created + 24*3600*cert->until;

		DBG(DBG_PARSING,
			DBG_log("L3 - until:");
			DBG_log("  %T", &cert->until, TRUE);
		)
	}

	/* public key algorithm - 1 byte */
	DBG(DBG_PARSING,
		DBG_log("L3 - public key algorithm:")
	)

	switch (pgp_size(packet, 1))
	{
	case PGP_PUBKEY_ALG_RSA:
	case PGP_PUBKEY_ALG_RSA_SIGN_ONLY:
		cert->pubkeyAlg = PUBKEY_ALG_RSA;
		DBG(DBG_PARSING,
			DBG_log("  RSA")
		)
		/* modulus n */
		cert->modulus.len = (pgp_size(packet, 2)+7) / BITS_PER_BYTE;
		cert->modulus.ptr = packet->ptr;
		packet->ptr += cert->modulus.len;
		packet->len -= cert->modulus.len;
		DBG(DBG_PARSING,
			DBG_log("L3 - modulus:")
		)
		DBG_cond_dump_chunk(DBG_RAW, "", cert->modulus);

		/* public exponent e */
		cert->publicExponent.len = (pgp_size(packet, 2)+7) / BITS_PER_BYTE;
		cert->publicExponent.ptr = packet->ptr;
		packet->ptr += cert->publicExponent.len;
		packet->len -= cert->publicExponent.len;
		DBG(DBG_PARSING,
			DBG_log("L3 - public exponent:")
		)
		DBG_cond_dump_chunk(DBG_RAW, "", cert->publicExponent);

		if (version == 3)
		{
			/* a V3 fingerprint is the MD5 hash of modulus and public exponent */
			MD5_CTX context;
			MD5Init(&context);
			MD5Update(&context, cert->modulus.ptr, cert->modulus.len);
			MD5Update(&context, cert->publicExponent.ptr, cert->publicExponent.len);
			MD5Final(cert->fingerprint, &context);
		}
		else
		{
			plog("  computation of V4 key ID not implemented yet");
		}
		break;
	case PGP_PUBKEY_ALG_DSA:
		cert->pubkeyAlg = PUBKEY_ALG_DSA;
		DBG(DBG_PARSING,
			DBG_log("  DSA")
		)
		plog("  DSA public keys not supported");
		return FALSE;
	 default:
		cert->pubkeyAlg = 0;
		DBG(DBG_PARSING,
			DBG_log("  other")
		)
		plog(" exotic not RSA public keys not supported");
		return FALSE;
	}
	return TRUE;
}

/*
 * Parse OpenPGP secret key packet defined in section 5.5.3 of RFC 2440
 */
static bool
parse_pgp_secretkey_packet(chunk_t *packet, RSA_private_key_t *key)
{
	int i, s2k;
	pgpcert_t cert = empty_pgpcert;

	if (!parse_pgp_pubkey_packet(packet, &cert))
		return FALSE;

	init_RSA_public_key((RSA_public_key_t *)key, cert.publicExponent
											   , cert.modulus);

	/* string-to-key usage */
	s2k = pgp_size(packet, 1);

	DBG(DBG_PARSING,
		DBG_log("L3 - string-to-key:  %d", s2k)
	)

	if (s2k == 255)
	{
		plog("  string-to-key specifiers not supported");
		return FALSE;
	}

	if (s2k >= PGP_SYM_ALG_ROOF)
	{
		plog("  undefined symmetric key algorithm");
		return FALSE;
	}

	/* a known symmetric key algorithm is specified*/
	DBG(DBG_PARSING,
		DBG_log("  %s", pgp_sym_alg_name[s2k])
	)

	/* private key is unencrypted */
	if (s2k == PGP_SYM_ALG_PLAIN)
	{
		for (i = 2; i < RSA_PRIVATE_FIELD_ELEMENTS; i++)
		{
			mpz_t u;  /* auxiliary variable */

			/* compute offset to private key component i*/
			MP_INT *n = (MP_INT*)((char *)key + RSA_private_field[i].offset);

			switch (i)
			{
			case 2:
			case 3:
			case 4:
				{
					size_t len = (pgp_size(packet, 2)+7) / BITS_PER_BYTE;

					n_to_mpz(n, packet->ptr, len);
					DBG(DBG_PARSING,
						DBG_log("L3 - %s:", RSA_private_field[i].name)
					)
					DBG_cond_dump(DBG_PRIVATE, "", packet->ptr, len);
					packet->ptr += len;
					packet->len -= len;
				}
				break;
			case 5:             /* dP = d mod (p-1) */
				mpz_init(u);
				mpz_sub_ui(u, &key->p, 1);
				mpz_mod(n, &key->d, u);
				mpz_clear(u);
				break;
			case 6:             /* dQ = d mod (q-1) */
				mpz_init(u);
				mpz_sub_ui(u, &key->q, 1);
				mpz_mod(n, &key->d, u);
				mpz_clear(u);
				break;
			case 7:             /* qInv = (q^-1) mod p */
				mpz_invert(n, &key->q, &key->p);
				if (mpz_cmp_ui(n, 0) < 0)
					mpz_add(n, n, &key->p);
				passert(mpz_cmp(n, &key->p) < 0);
				break;
			}
		}
		return TRUE;
	}

	plog("  %s encryption not supported",  pgp_sym_alg_name[s2k]);
	return FALSE;
}

/*
 * Parse OpenPGP signature packet defined in section 5.2.2 of RFC 2440
 */
static bool
parse_pgp_signature_packet(chunk_t *packet, pgpcert_t *cert)
{
	time_t created;
	chunk_t keyid;
	u_char  sig_type;
	u_char version = pgp_version(packet);

	/* we parse only V3 signature packets */
	if (version != 3)
		return TRUE;

	/* size byte must have the value 5 */
	if (pgp_size(packet, 1) != 5)
	{
		plog(" size must be 5");
		return FALSE;
	}

	/* signature type - 1 byte */
	sig_type = (u_char)pgp_size(packet, 1);
	DBG(DBG_PARSING,
		DBG_log("L3 - signature type:  0x%2x", sig_type)
	)

	/* creation date - 4 bytes */
	created = (time_t)pgp_size(packet, 4);
	DBG(DBG_PARSING,
		DBG_log("L3 - created:");
		DBG_log("  %T", &cert->created, TRUE)
	)

	/* key ID of signer - 8 bytes */
	keyid.ptr = packet->ptr;
	keyid.len = PGP_KEYID_SIZE;
	DBG_cond_dump_chunk(DBG_PARSING, "L3 - key ID of signer", keyid);

   return TRUE;
}

bool
parse_pgp(chunk_t blob, pgpcert_t *cert, RSA_private_key_t *key)
{
	DBG(DBG_PARSING,
		DBG_log("L0 - PGP file:")
	)
	DBG_cond_dump_chunk(DBG_RAW, "", blob);

	if (cert != NULL)
	{
		/* parse a PGP certificate file */
		cert->certificate = blob;
		time(&cert->installed);
	}
	else if (key == NULL)
	{
		/* should not occur, nothing to parse */
		return FALSE;
	}

	while (blob.len > 0)
	{
		chunk_t packet = chunk_empty;
		u_char packet_tag = *blob.ptr;

		DBG(DBG_PARSING,
			DBG_log("L1 - PGP packet:  tag= 0x%2x", packet_tag)
		)

		/* bit 7 must be set */
		if (!(packet_tag & 0x80))
		{
			plog("  incorrect Packet Tag");
			return FALSE;
		}

		/* bit 6 set defines new packet format */
		if (packet_tag & 0x40)
		{
			plog("  new PGP packet format not supported");
			return FALSE;
		}
		else
		{
			int packet_type = (packet_tag & 0x3C) >> 2;

			packet.len = pgp_old_packet_length(&blob);
			packet.ptr = blob.ptr;
			blob.ptr += packet.len;
			blob.len -= packet.len;
			DBG(DBG_PARSING,
				DBG_log("  %s (%d), old format, %d bytes",
					(packet_type < PGP_PKT_ROOF) ?
					pgp_packet_type_name[packet_type] :
					"Undefined Packet Type", packet_type, (int)packet.len);
				DBG_log("L2 - body:")
			)
			DBG_cond_dump_chunk(DBG_RAW, "", packet);

			if (cert != NULL)
			{
				/* parse a PGP certificate */
				switch (packet_type)
				{
				case PGP_PKT_PUBLIC_KEY:
					if (!parse_pgp_pubkey_packet(&packet, cert))
						return FALSE;
					break;
				case PGP_PKT_SIGNATURE:
					if (!parse_pgp_signature_packet(&packet, cert))
						return FALSE;
					break;
				case PGP_PKT_USER_ID:
					DBG(DBG_PARSING,
						DBG_log("L3 - user ID:");
						DBG_log("  '%.*s'", (int)packet.len, packet.ptr)
					)
					break;
				default:
					break;
				}
			}
			else
			{
				/* parse a PGP private key file */
				switch (packet_type)
				{
				case PGP_PKT_SECRET_KEY:
					if (!parse_pgp_secretkey_packet(&packet, key))
						return FALSE;
					break;
				default:
					break;
				}
			}
		}
	}
	return TRUE;
}

/*
 *  compare two OpenPGP certificates
 */
static bool
same_pgpcert(pgpcert_t *a, pgpcert_t *b)
{
	return a->certificate.len == b->certificate.len &&
		memeq(a->certificate.ptr, b->certificate.ptr, b->certificate.len);
}

/*
 * for each link pointing to the certificate increase the count by one
 */
void
share_pgpcert(pgpcert_t *cert)
{
	if (cert != NULL)
	{
		cert->count++;
	}
}

/*
 * select the OpenPGP keyid as ID
 */
void
select_pgpcert_id(pgpcert_t *cert, struct id *end_id)
{
	end_id->kind = ID_KEY_ID;
	end_id->name.len = PGP_FINGERPRINT_SIZE;
	end_id->name.ptr = cert->fingerprint;
	end_id->name.ptr = temporary_cyclic_buffer();
	memcpy(end_id->name.ptr, cert->fingerprint, PGP_FINGERPRINT_SIZE);
}

/*
 *  add an OpenPGP user/host certificate to the chained list
 */
pgpcert_t*
add_pgpcert(pgpcert_t *cert)
{
	pgpcert_t *c = pgpcerts;

	while (c != NULL)
	{
		if (same_pgpcert(c, cert)) /* already in chain, free cert */
		{
			free_pgpcert(cert);
			return c;
		}
		c = c->next;
	}

	/* insert new cert at the root of the chain */
	cert->next = pgpcerts;
	pgpcerts = cert;
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  pgp cert inserted")
	)
	return cert;
}

/*  release of a certificate decreases the count by one
 "  the certificate is freed when the counter reaches zero
 */
void
release_pgpcert(pgpcert_t *cert)
{
	if (cert != NULL && --cert->count == 0)
	{
		pgpcert_t **pp = &pgpcerts;
		while (*pp != cert)
			pp = &(*pp)->next;
		*pp = cert->next;
		free_pgpcert(cert);
	}
}

/*
 *  free a PGP certificate
 */
void
free_pgpcert(pgpcert_t *cert)
{
	if (cert != NULL)
	{
		free(cert->certificate.ptr);
		free(cert);
	}
}

/*
 *  list all PGP end certificates in a chained list
 */
void
list_pgp_end_certs(bool utc)
{
   pgpcert_t *cert = pgpcerts;
   time_t now;

	/* determine the current time */
	time(&now);

	if (cert != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of PGP End certificates:");
		whack_log(RC_COMMENT, " ");
	}

	while (cert != NULL)
	{
		unsigned keysize;
		char buf[BUF_LEN];
		cert_t c;

		c.type = CERT_PGP;
		c.u.pgp = cert;

		whack_log(RC_COMMENT, "%T, count: %d", &cert->installed, utc), cert->count;
		datatot(cert->fingerprint, PGP_FINGERPRINT_SIZE, 'x', buf, BUF_LEN);
		whack_log(RC_COMMENT, "       fingerprint:  %s", buf);
		form_keyid(cert->publicExponent, cert->modulus, buf, &keysize);
		whack_log(RC_COMMENT, "       pubkey:   %4d RSA Key %s%s", 8*keysize, buf,
				(has_private_key(c))? ", has private key" : "");
		whack_log(RC_COMMENT, "       created:  %T", &cert->created, utc);
		whack_log(RC_COMMENT, "       until:    %T %s", &cert->until, utc,
				check_expiry(cert->until, CA_CERT_WARNING_INTERVAL, TRUE));
		cert = cert->next;
	}
}

