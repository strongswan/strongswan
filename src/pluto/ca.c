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
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <utils/identification.h>

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

static x509cert_t *x509authcerts = NULL;

/* chained list of X.509 certification authority information records */

static ca_info_t *ca_infos = NULL;

/*
 * Checks if CA a is trusted by CA b
 */
bool trusted_ca(chunk_t a, chunk_t b, int *pathlen)
{
	bool match = FALSE;

	/* no CA b specified -> any CA a is accepted */
	if (b.ptr == NULL)
	{
		*pathlen = (a.ptr == NULL)? 0 : MAX_CA_PATH_LEN;
		return TRUE;
	}

	/* no CA a specified -> trust cannot be established */
	if (a.ptr == NULL)
	{
		*pathlen = MAX_CA_PATH_LEN;
		return FALSE;
	}

	*pathlen = 0;

	/* CA a equals CA b -> we have a match */
	if (same_dn(a, b))
	{
		return TRUE;
	}

	/* CA a might be a subordinate CA of b */
	lock_authcert_list("trusted_ca");

	while ((*pathlen)++ < MAX_CA_PATH_LEN)
	{
		certificate_t *certificate;
		identification_t *issuer;
		chunk_t issuer_dn;
		x509cert_t *cacert;

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
		issuer_dn = issuer->get_encoding(issuer);
		match = same_dn(issuer_dn, b);

		/* we have a match and exit the loop */
		if (match)
		{
			break;
		}
		/* go one level up in the CA chain */
		a = issuer_dn;
	}

	unlock_authcert_list("trusted_ca");
	return match;
}

/*
 * does our CA match one of the requested CAs?
 */
bool match_requested_ca(generalName_t *requested_ca, chunk_t our_ca,
						int *our_pathlen)
{
	/* if no ca is requested than any ca will match */
	if (requested_ca == NULL)
	{
		*our_pathlen = 0;
		return TRUE;
	}

	*our_pathlen = MAX_CA_PATH_LEN + 1;

	while (requested_ca != NULL)
	{
		int pathlen;

		if (trusted_ca(our_ca, requested_ca->name, &pathlen)
		&& pathlen < *our_pathlen)
		{
			*our_pathlen = pathlen;
		}
		requested_ca = requested_ca->next;
	}

	if (*our_pathlen > MAX_CA_PATH_LEN)
	{
		*our_pathlen = MAX_CA_PATH_LEN;
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
	x509cert_t *first = x509authcerts;
	x509authcerts = first->next;
	free_x509cert(first);
}

/*
 *  free  all CA certificates
 */
void free_authcerts(void)
{
	lock_authcert_list("free_authcerts");

	while (x509authcerts != NULL)
		free_first_authcert();

	unlock_authcert_list("free_authcerts");
}

/*
 *  get a X.509 authority certificate with a given subject or keyid
 */
x509cert_t* get_authcert(chunk_t subject, chunk_t keyid, x509_flag_t auth_flags)
{
	x509cert_t *cert, *prev_cert = NULL;

	/* the authority certificate list is empty */
	if (x509authcerts == NULL)
	{
		return NULL;
	}

	for (cert = x509authcerts; cert != NULL; prev_cert = cert, cert = cert->next)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *cert_subject;
		chunk_t cert_subject_dn;

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
		cert_subject = certificate->get_subject(certificate);
		cert_subject_dn = cert_subject->get_encoding(cert_subject);
		if (!same_dn(subject, cert_subject_dn))
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
x509cert_t* add_authcert(x509cert_t *cert, x509_flag_t auth_flags)
{
	certificate_t *certificate = cert->cert;
	x509_t *x509 = (x509_t*)certificate;
	identification_t *cert_subject = certificate->get_subject(certificate);
	chunk_t cert_subject_dn = cert_subject->get_encoding(cert_subject);
	x509cert_t *old_cert;

	lock_authcert_list("add_authcert");

	old_cert = get_authcert(cert_subject_dn, 
							x509->get_subjectKeyIdentifier(x509),
							auth_flags);
	if (old_cert != NULL)
	{
		if (certificate->equals(certificate, old_cert->cert))
		{
			DBG(DBG_CONTROL | DBG_PARSING ,
				DBG_log("  authcert is already present and identical")
			)
			unlock_authcert_list("add_authcert");

			free_x509cert(cert);
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
	share_x509cert(cert);  /* set count to one */
	DBG(DBG_CONTROL | DBG_PARSING,
		DBG_log("  authcert inserted")
	)
	unlock_authcert_list("add_authcert");
	return cert;
}

/*
 *  Loads authority certificates
 */
void load_authcerts(const char *type, const char *path, x509_flag_t auth_flags)
{
	struct dirent **filelist;
	u_char buf[BUF_LEN];
	u_char *save_dir;
	int n;

	/* change directory to specified path */
	save_dir = getcwd(buf, BUF_LEN);

	if (chdir(path))
	{
		plog("Could not change to directory '%s'", path);
	}
	else
	{
		plog("Changing to directory '%s'", path);
		n = scandir(path, &filelist, file_select, alphasort);

		if (n < 0)
			plog("  scandir() error");
		else
		{
			while (n--)
			{
				cert_t cert;

				if (load_cert(filelist[n]->d_name, type, auth_flags, &cert))
				{
					add_authcert(cert.u.x509, auth_flags);
				}
				free(filelist[n]);
			}
			free(filelist);
		}
	}
	/* restore directory path */
	ignore_result(chdir(save_dir));
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
static const x509cert_t* get_alt_cacert(chunk_t subject, chunk_t keyid,
										const x509cert_t *cert)
{
	if (cert == NULL)
	{
		return NULL;
	}

	for (; cert != NULL; cert = cert->next)
	{
		certificate_t *certificate = cert->cert;
		identification_t *cert_subject;
		chunk_t cert_subject_dn;

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
		cert_subject = certificate->get_subject(certificate);
		cert_subject_dn = cert_subject->get_encoding(cert_subject);
		if (!same_dn(subject, cert_subject_dn))
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
bool trust_authcert_candidate(const x509cert_t *cert, const x509cert_t *alt_chain)
{
	int pathlen;

	lock_authcert_list("trust_authcert_candidate");

	for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
	{
		certificate_t *certificate = cert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *subject = certificate->get_subject(certificate);
		identification_t *issuer = certificate->get_issuer(certificate);
		chunk_t issuer_dn = issuer->get_encoding(issuer);
		chunk_t authKeyID = x509->get_authKeyIdentifier(x509);
		const x509cert_t *authcert = NULL;

		DBG(DBG_CONTROL,
			DBG_log("subject: '%Y'", subject);
			DBG_log("issuer:  '%Y'", issuer);
			if (authKeyID.ptr != NULL)
			{
				DBG_log("authkey:  %#B", &authKeyID);
			}
		)

		/* search in alternative chain first */
		authcert = get_alt_cacert(issuer_dn, authKeyID, alt_chain);

		if (authcert != NULL)
		{
			DBG(DBG_CONTROL,
				DBG_log("issuer cacert found in alternative chain")
			)
		}
		else
		{
			/* search in trusted chain */
			authcert = get_authcert(issuer_dn, authKeyID, X509_CA);

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
	plog("maximum ca path length of %d levels exceeded", MAX_CA_PATH_LEN);
	unlock_authcert_list("trust_authcert_candidate");
	return FALSE;
}

/*
 *  get a CA info record with a given authName or authKeyID
 */
ca_info_t* get_ca_info(chunk_t authname, chunk_t keyid)
{
	ca_info_t *ca= ca_infos;

	while (ca!= NULL)
	{
		if ((keyid.ptr != NULL) ? same_keyid(keyid, ca->authKeyID)
			: same_dn(authname, ca->authName))
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
	free(ca_info->name);
	free(ca_info->ldaphost);
	free(ca_info->ldapbase);
	free(ca_info->ocspuri);
	free(ca_info->authName.ptr);
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
	cert_t cert;
	bool valid_cert = FALSE;
	bool cached_cert = FALSE;

	if (find_ca_info_by_name(msg->name, FALSE))
	{
		loglog(RC_DUPNAME, "attempt to redefine ca record \"%s\"", msg->name);
		return;
	}

	if (scx_on_smartcard(msg->cacert))
	{
		/* load CA cert from smartcard */
		valid_cert = scx_load_cert(msg->cacert, &sc, &cert, &cached_cert);
	}
	else
	{
		/* load CA cert from file */
		valid_cert = load_ca_cert(msg->cacert, &cert);
	}

	if (valid_cert)
	{
		x509cert_t *cacert = cert.u.x509;
		certificate_t *certificate = cacert->cert;
		x509_t *x509 = (x509_t*)certificate;
		identification_t *subject = certificate->get_subject(certificate);
		chunk_t subject_dn = subject->get_encoding(subject);
		chunk_t subjectKeyID = x509->get_subjectKeyIdentifier(x509);
		ca_info_t *ca = NULL;

		/* does the authname already exist? */
		ca = get_ca_info(subject_dn, subjectKeyID);

		if (ca != NULL)
		{
			/* ca_info is already present */
			loglog(RC_DUPNAME, "  duplicate ca information in record \"%s\" found,"
							   "ignoring \"%s\"", ca->name, msg->name);
			free_x509cert(cacert);
			return;
		}

		plog("added ca description \"%s\"", msg->name);

		/* create and initialize new ca_info record */
		ca = create_ca_info();

		/* name */
		ca->name = clone_str(msg->name);

		/* authName */
		ca->authName = chunk_clone(subject_dn);
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
				plog("  ignoring ocspuri with unkown protocol");
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
		cacert = add_authcert(cacert, X509_CA);
		if (!cached_cert && sc != NULL)
		{
			if (sc->last_cert.type == CERT_X509_SIGNATURE)
				sc->last_cert.u.x509->count--;
			sc->last_cert.u.x509 = cacert;
			share_cert(sc->last_cert);
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
		u_char buf[BUF_LEN];

		/* strictpolicy per CA not supported yet
		 *
		whack_log(RC_COMMENT, "%T, \"%s\", strictcrlpolicy: %s"
				, &ca->installed, utc, ca->name
				, ca->strictcrlpolicy? "yes":"no");
		*/
		whack_log(RC_COMMENT, " ");
		dntoa(buf, BUF_LEN, ca->authName);
		whack_log(RC_COMMENT, "  authname: \"%s\"", buf);
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

		if (ca->authKeyID.ptr != NULL)
		{
			datatot(ca->authKeyID.ptr, ca->authKeyID.len, ':'
				, buf, BUF_LEN);
			whack_log(RC_COMMENT, "  authkey:   %s", buf);
		}
		ca = ca->next;
	}
}

