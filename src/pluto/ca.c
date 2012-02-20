/* Certification Authority (CA) support for IKE authentication
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <debug.h>
#include <utils/enumerator.h>
#include <credentials/certificates/x509.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "x509.h"
#include "ca.h"
#include "certs.h"
#include "whack.h"
#include "fetch.h"
#include "smartcard.h"

/* chained list of X.509 authority certificates (ca, aa, and ocsp) */

static cert_t *x509authcerts = NULL;

/* chained list of X.509 certification authority information records */

static ca_info_t *ca_infos = NULL;

/*
 * Checks if CA a is trusted by CA b
 */
bool trusted_ca(identification_t *a, identification_t *b, int *pathlen)
{
	bool match = FALSE;

	/* no CA b specified -> any CA a is accepted */
	if (b == NULL)
	{
		*pathlen = (a == NULL) ? 0 : X509_MAX_PATH_LEN;
		return TRUE;
	}

	/* no CA a specified -> trust cannot be established */
	if (a == NULL)
	{
		*pathlen = X509_MAX_PATH_LEN;
		return FALSE;
	}

	*pathlen = 0;

	/* CA a equals CA b -> we have a match */
	if (a->equals(a, b))
	{
		return TRUE;
	}

	/* CA a might be a subordinate CA of b */
	lock_authcert_list("trusted_ca");

	while ((*pathlen)++ < X509_MAX_PATH_LEN)
	{
		certificate_t *certificate;
		identification_t *issuer;
		cert_t *cacert;

		cacert = get_authcert(a, chunk_empty, X509_CA);
		if (cacert == NULL)
		{
			break;
		}
		certificate = cacert->cert;

		/* is the certificate self-signed? */
		{
			x509_t *x509 = (x509_t*)certificate;

			if (x509->get_flags(x509) & X509_SELF_SIGNED)
			{
				break;
			}
		}

		/* does the issuer of CA a match CA b? */
		issuer = certificate->get_issuer(certificate);
		match = b->equals(b, issuer);

		/* we have a match and exit the loop */
		if (match)
		{
			break;
		}
		/* go one level up in the CA chain */
		a = issuer;
	}

	unlock_authcert_list("trusted_ca");
	return match;
}

/*
 * does our CA match one of the requested CAs?
 */
bool match_requested_ca(linked_list_t *requested_ca, identification_t *our_ca,
						int *our_pathlen)
{
	identification_t *ca;
	enumerator_t *enumerator;

	/* if no ca is requested than any ca will match */
	if (requested_ca == NULL || requested_ca->get_count(requested_ca) == 0)
	{
		*our_pathlen = 0;
		return TRUE;
	}

	*our_pathlen = X509_MAX_PATH_LEN + 1;

	enumerator = requested_ca->create_enumerator(requested_ca);
	while (enumerator->enumerate(enumerator, &ca))
	{
		int pathlen;

		if (trusted_ca(our_ca, ca, &pathlen) && pathlen < *our_pathlen)
		{
			*our_pathlen = pathlen;
		}
	}
	enumerator->destroy(enumerator);

	if (*our_pathlen > X509_MAX_PATH_LEN)
	{
		*our_pathlen = X509_MAX_PATH_LEN;
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

/*
 *  free the first authority certificate in the chain
 */
static void free_first_authcert(void)
{
	cert_t *first = x509authcerts;

	x509authcerts = first->next;
	cert_free(first);
}

/*
 *  free  all CA certificates
 */
void free_authcerts(void)
{
	lock_authcert_list("free_authcerts");

	while (x509authcerts != NULL)
	{
		free_first_authcert();
	}
	unlock_authcert_list("free_authcerts");
}

/*
 *  get a X.509 authority certificate with a given subject or keyid
 */
cert_t* get_authcert(identification_t *subject, chunk_t keyid,
						 x509_flag_t auth_flags)
{
	cert_t *cert, *prev_cert = NULL;

	/* the authority certificate list is empty */
	if (x509authcerts == NULL)
	{
		return NULL;
	}

	for (cert = x509authcerts; cert != NULL; prev_cert = cert, cert = cert->next)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;

		/* skip non-matching types of authority certificates */
		if (!(x509->get_flags(x509) & auth_flags))
		{
			continue;
		}

		/* compare the keyid with the certificate's subjectKeyIdentifier */
		if (keyid.ptr)
		{
			chunk_t subjectKeyId;

			subjectKeyId = x509->get_subjectKeyIdentifier(x509);
			if (subjectKeyId.ptr && !chunk_equals(keyid, subjectKeyId))
			{
				continue;
			}
		}

		/* compare the subjectDistinguishedNames */
		if (!(subject && certificate->has_subject(certificate, subject)) &&
			 (subject || !keyid.ptr))
		{
			continue;
		}

		/* found the authcert */
		if (cert != x509authcerts)
		{
			/* bring the certificate up front */
			prev_cert->next = cert->next;
			cert->next = x509authcerts;
			x509authcerts = cert;
		}
		return cert;
	}
	return NULL;
}

/*
 * add an authority certificate to the chained list
 */
cert_t* add_authcert(cert_t *cert, x509_flag_t auth_flags)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	cert_t *old_cert;

	lock_authcert_list("add_authcert");

	old_cert = get_authcert(certificate->get_subject(certificate),
							x509->get_subjectKeyIdentifier(x509),
							auth_flags);
	if (old_cert)
	{
		if (certificate->equals(certificate, old_cert->cert))
		{
			DBG(DBG_CONTROL | DBG_PARSING ,
				DBG_log("  authcert is already present and identical")
			)
			unlock_authcert_list("add_authcert");

			cert_free(cert);
			return old_cert;
		}
		else
		{
			/* cert is already present but will be replaced by new cert */
			free_first_authcert();
			DBG(DBG_CONTROL | DBG_PARSING ,
				DBG_log("  existing authcert deleted")
			)
		}
	}

	/* add new authcert to chained list */
	cert->next = x509authcerts;
	x509authcerts = cert;
	cert_share(cert);  /* set count to one */
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  authcert inserted")
	)
	unlock_authcert_list("add_authcert");
	return cert;
}

/*
 *  Loads authority certificates
 */
void load_authcerts(char *type, char *path, x509_flag_t auth_flags)
{
	enumerator_t *enumerator;
	struct stat st;
	char *file;

	DBG1(DBG_LIB, "loading %s certificates from '%s'", type, path);

	enumerator = enumerator_create_directory(path);
	if (!enumerator)
	{
		DBG1(DBG_LIB, "  reading directory '%s' failed", path);
		return;
	}

	while (enumerator->enumerate(enumerator, NULL, &file, &st))
	{
		cert_t *cert;

		if (!S_ISREG(st.st_mode))
		{
			/* skip special file */
			continue;
		}
		cert = load_cert(file, type, auth_flags);
		if (cert)
		{
			add_authcert(cert, auth_flags);
		}
	}
	enumerator->destroy(enumerator);
}

/*
 *  list all X.509 authcerts with given auth flags in a chained list
 */
void list_authcerts(const char *caption, x509_flag_t auth_flags, bool utc)
{
	lock_authcert_list("list_authcerts");
	list_x509cert_chain(caption, x509authcerts, auth_flags, utc);
	unlock_authcert_list("list_authcerts");
}

/*
 * get a cacert with a given subject or keyid from an alternative list
 */
static const cert_t* get_alt_cacert(identification_t *subject, chunk_t keyid,
										const cert_t *cert)
{
	if (cert == NULL)
	{
		return NULL;
	}
	for (; cert != NULL; cert = cert->next)
	{
		certificate_t *certificate = cert->cert;

		/* compare the keyid with the certificate's subjectKeyIdentifier */
		if (keyid.ptr)
		{
			x509_t *x509 = (x509_t*)certificate;
			chunk_t subjectKeyId;

			subjectKeyId = x509->get_subjectKeyIdentifier(x509);
			if (subjectKeyId.ptr && !chunk_equals(keyid, subjectKeyId))
			{
				continue;
			}
		}

		/* compare the subjectDistinguishedNames */
		if (!certificate->has_subject(certificate, subject))
		{
			continue;
		}

		/* we found the cacert */
		return cert;
	}
	return NULL;
}

/* establish trust into a candidate authcert by going up the trust chain.
 * validity and revocation status are not checked.
 */
bool trust_authcert_candidate(const cert_t *cert, const cert_t *alt_chain)
{
	int pathlen;

	lock_authcert_list("trust_authcert_candidate");

	for (pathlen = 0; pathlen < X509_MAX_PATH_LEN; pathlen++)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer = certificate->get_issuer(certificate);
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		const cert_t *authcert = NULL;

		DBG(DBG_CONTROL,
			DBG_log("subject: '%Y'", subject);
			DBG_log("issuer:  '%Y'", issuer);
			if (authKeyID.ptr != NULL)
			{
				DBG_log("authkey:  %#B", &authKeyID);
			}
		)

		/* search in alternative chain first */
		authcert = get_alt_cacert(issuer, authKeyID, alt_chain);

		if (authcert != NULL)
		{
			DBG(DBG_CONTROL,
				DBG_log("issuer cacert found in alternative chain")
			)
		}
		else
		{
			/* search in trusted chain */
			authcert = get_authcert(issuer, authKeyID, X509_CA);

			if (authcert != NULL)
			{
				DBG(DBG_CONTROL,
					DBG_log("issuer cacert found")
				)
			}
			else
			{
				plog("issuer cacert not found");
				unlock_authcert_list("trust_authcert_candidate");
				return FALSE;
			}
		}

		if (!certificate->issued_by(certificate, authcert->cert))
		{
			plog("certificate signature is invalid");
			unlock_authcert_list("trust_authcert_candidate");
			return FALSE;
		}
		DBG(DBG_CONTROL,
			DBG_log("certificate signature is valid")
		)

		/* check if cert is a self-signed root ca */
		if (pathlen > 0 && (x509->get_flags(x509) & X509_SELF_SIGNED))
		{
			DBG(DBG_CONTROL,
				DBG_log("reached self-signed root ca")
			)
			unlock_authcert_list("trust_authcert_candidate");
			return TRUE;
		}

		/* go up one step in the trust chain */
		cert = authcert;
	}
	plog("maximum ca path length of %d levels exceeded", X509_MAX_PATH_LEN);
	unlock_authcert_list("trust_authcert_candidate");
	return FALSE;
}

/*
 *  get a CA info record with a given authName or authKeyID
 */
ca_info_t* get_ca_info(identification_t *name, chunk_t keyid)
{
	ca_info_t *ca= ca_infos;

	while (ca != NULL)
	{
		if ((keyid.ptr) ? same_keyid(keyid, ca->authKeyID)
			: name->equals(name, ca->authName))
		{
			return ca;
		}
		ca = ca->next;
	}
	return NULL;
}


/*
 *  free the dynamic memory used by a ca_info record
 */
static void
free_ca_info(ca_info_t* ca_info)
{
	if (ca_info == NULL)
	{
		return;
	}
	ca_info->crluris->destroy_function(ca_info->crluris, free);
	DESTROY_IF(ca_info->authName);
	free(ca_info->name);
	free(ca_info->ldaphost);
	free(ca_info->ldapbase);
	free(ca_info->ocspuri);
	free(ca_info->authKeyID.ptr);
	free(ca_info);
}

/*
 *  free  all CA certificates
 */
void free_ca_infos(void)
{
	while (ca_infos != NULL)
	{
		ca_info_t *ca = ca_infos;

		ca_infos = ca_infos->next;
		free_ca_info(ca);
	}
}

/*
 * find a CA information record by name and optionally delete it
 */
bool find_ca_info_by_name(const char *name, bool delete)
{
	ca_info_t **ca_p = &ca_infos;
	ca_info_t *ca = *ca_p;

	while (ca != NULL)
	{
		/* is there already an entry? */
		if (streq(name, ca->name))
		{
			if (delete)
			{
				lock_ca_info_list("find_ca_info_by_name");
				*ca_p = ca->next;
				free_ca_info(ca);
				plog("deleting ca description \"%s\"", name);
				unlock_ca_info_list("find_ca_info_by_name");
			}
			return TRUE;
		}
		ca_p = &ca->next;
		ca = *ca_p;
	}
	return FALSE;
}

/*
 * Create an empty ca_info_t record
 */
ca_info_t* create_ca_info(void)
{
	ca_info_t *ca_info = malloc_thing(ca_info_t);

	memset(ca_info, 0, sizeof(ca_info_t));
	ca_info->crluris = linked_list_create();

	return ca_info;
}

/**
 * Adds a CA description to a chained list
 */
void add_ca_info(const whack_message_t *msg)
{
	smartcard_t *sc = NULL;
	cert_t *cert = NULL;
	bool cached_cert = FALSE;

	if (find_ca_info_by_name(msg->name, FALSE))
	{
		loglog(RC_DUPNAME, "attempt to redefine ca record \"%s\"", msg->name);
		return;
	}

	if (scx_on_smartcard(msg->cacert))
	{
		/* load CA cert from smartcard */
		cert = scx_load_cert(msg->cacert, &sc, &cached_cert);
	}
	else
	{
		/* load CA cert from file */
		cert = load_ca_cert(msg->cacert);
	}

	if (cert)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *subject = certificate->get_subject(certificate);
		chunk_t subjectKeyID = x509->get_subjectKeyIdentifier(x509);
		ca_info_t *ca = NULL;

		/* does the authname already exist? */
		ca = get_ca_info(subject, subjectKeyID);

		if (ca != NULL)
		{
			/* ca_info is already present */
			loglog(RC_DUPNAME, "  duplicate ca information in record \"%s\" found,"
							   "ignoring \"%s\"", ca->name, msg->name);
			cert_free(cert);
			return;
		}

		plog("added ca description \"%s\"", msg->name);

		/* create and initialize new ca_info record */
		ca = create_ca_info();

		/* name */
		ca->name = clone_str(msg->name);

		/* authName */
		ca->authName = subject->clone(subject);
		DBG(DBG_CONTROL,
			DBG_log("authname: '%Y'", subject)
		)

		/* authKeyID */
		if (subjectKeyID.ptr)
		{
			ca->authKeyID = chunk_clone(subjectKeyID);
			DBG(DBG_CONTROL | DBG_PARSING ,
				DBG_log("authkey:  %#B", &subjectKeyID)
			)
		}

		/* ldaphost */
		ca->ldaphost = clone_str(msg->ldaphost);

		/* ldapbase */
		ca->ldapbase = clone_str(msg->ldapbase);

		/* ocspuri */
		if (msg->ocspuri != NULL)
		{
			if (strncasecmp(msg->ocspuri, "http", 4) == 0)
				ca->ocspuri = clone_str(msg->ocspuri);
			else
				plog("  ignoring ocspuri with unknown protocol");
		}

		/* add crl uris */
		add_distribution_point(ca->crluris, msg->crluri);
		add_distribution_point(ca->crluris, msg->crluri2);

		/* strictrlpolicy */
		ca->strictcrlpolicy = msg->whack_strict;

		/* insert ca_info record into the chained list */
		lock_ca_info_list("add_ca_info");

		ca->next = ca_infos;
		ca_infos = ca;

		unlock_ca_info_list("add_ca_info");

		/* add cacert to list of authcerts */
		cert = add_authcert(cert, X509_CA);
		if (!cached_cert && sc != NULL)
		{
			if (sc->last_cert != NULL)
			{
				sc->last_cert->count--;
			}
			sc->last_cert = cert;
			cert_share(sc->last_cert);
		}
		if (sc != NULL)
			time(&sc->last_load);
	}
}

/*
 * list all ca_info records in the chained list
 */
void list_ca_infos(bool utc)
{
	ca_info_t *ca = ca_infos;

	if (ca != NULL)
	{
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of X.509 CA Information Records:");
	}

	while (ca != NULL)
	{
		/* strictpolicy per CA not supported yet
		 *
		whack_log(RC_COMMENT, "%T, \"%s\", strictcrlpolicy: %s"
				, &ca->installed, utc, ca->name
				, ca->strictcrlpolicy? "yes":"no");
		*/
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "  authname: \"%Y\"", ca->authName);
		if (ca->ldaphost)
		{
			whack_log(RC_COMMENT, "  ldaphost: '%s'", ca->ldaphost);
		}
		if (ca->ldapbase)
		{
			whack_log(RC_COMMENT, "  ldapbase: '%s'", ca->ldapbase);
		}
		if (ca->ocspuri)
		{
			whack_log(RC_COMMENT, "  ocspuri:  '%s'", ca->ocspuri);
		}

		list_distribution_points(ca->crluris);

		if (ca->authKeyID.ptr)
		{
			whack_log(RC_COMMENT, "  authkey:   %#B", &ca->authKeyID);
		}
		ca = ca->next;
	}
}

