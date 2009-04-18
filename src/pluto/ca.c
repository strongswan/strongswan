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
 *
 * RCSID $Id$
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <freeswan.h>
#include <ipsec_policy.h>

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

const ca_info_t empty_ca_info = {
      NULL	  ,  /* next */
      NULL	  ,  /* name */
    UNDEFINED_TIME,
    { NULL, 0 }	  ,  /* authName */
    { NULL, 0 }	  ,  /* authKeyID */
    { NULL, 0 }	  ,  /* authKey SerialNumber */
      NULL	  ,  /* ldaphost */
      NULL	  ,  /* ldapbase */
      NULL	  ,  /* ocspori */
      NULL	  ,  /* crluri */
      FALSE	     /* strictcrlpolicy */
};

/* chained list of X.509 certification authority information records */

static ca_info_t *ca_infos = NULL;

/*
 * Checks if CA a is trusted by CA b
 */
bool
trusted_ca(chunk_t a, chunk_t b, int *pathlen)
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
	return TRUE;

    /* CA a might be a subordinate CA of b */
    lock_authcert_list("trusted_ca");

    while ((*pathlen)++ < MAX_CA_PATH_LEN)
    {
	x509cert_t *cacert = get_authcert(a, chunk_empty, chunk_empty, AUTH_CA);

	/* cacert not found or self-signed root cacert-> exit */
	if (cacert == NULL || same_dn(cacert->issuer, a))
	    break;

	/* does the issuer of CA a match CA b? */
	match = same_dn(cacert->issuer, b);

	/* we have a match and exit the loop */
	if (match)
	    break;

	/* go one level up in the CA chain */
	a = cacert->issuer;
    }
    
    unlock_authcert_list("trusted_ca");
    return match;
}

/*
 * does our CA match one of the requested CAs?
 */
bool
match_requested_ca(generalName_t *requested_ca, chunk_t our_ca, int *our_pathlen)
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
static void
free_first_authcert(void)
{
    x509cert_t *first = x509authcerts;
    x509authcerts = first->next;
    free_x509cert(first);
}

/*
 *  free  all CA certificates
 */
void
free_authcerts(void)
{
    lock_authcert_list("free_authcerts");

    while (x509authcerts != NULL)
        free_first_authcert();

    unlock_authcert_list("free_authcerts");
}

/*
 *  get a X.509 authority certificate with a given subject or keyid
 */
x509cert_t*
get_authcert(chunk_t subject, chunk_t serial, chunk_t keyid, u_char auth_flags)
{
    x509cert_t *cert = x509authcerts;
    x509cert_t *prev_cert = NULL;

    while (cert != NULL)
    {
	if (cert->authority_flags & auth_flags
	&& ((keyid.ptr != NULL) ? same_keyid(keyid, cert->subjectKeyID)
	    : (same_dn(subject, cert->subject)
	       && same_serial(serial, cert->serialNumber))))
	{
	    if (cert != x509authcerts)
	    {
		/* bring the certificate up front */
		prev_cert->next = cert->next;
		cert->next = x509authcerts;
		x509authcerts = cert;
	    }
	    return cert;
	}
	prev_cert = cert;
	cert = cert->next;
    }
    return NULL;
}

/*
 * add an authority certificate to the chained list
 */
x509cert_t*
add_authcert(x509cert_t *cert, u_char auth_flags)
{
    x509cert_t *old_cert;

    /* set authority flags */
    cert->authority_flags |= auth_flags;

    lock_authcert_list("add_authcert");

    old_cert = get_authcert(cert->subject, cert->serialNumber
	, cert->subjectKeyID, auth_flags);

    if (old_cert != NULL)
    {
	if (same_x509cert(cert, old_cert))
	{
	    /* cert is already present, just add additional authority flags */
	    old_cert->authority_flags |= cert->authority_flags;
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
void
load_authcerts(const char *type, const char *path, u_char auth_flags)
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

		if (load_cert(filelist[n]->d_name, type, &cert))
		    add_authcert(cert.u.x509, auth_flags);

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
void
list_authcerts(const char *caption, u_char auth_flags, bool utc)
{
    lock_authcert_list("list_authcerts");
    list_x509cert_chain(caption, x509authcerts, auth_flags, utc);
    unlock_authcert_list("list_authcerts");
}

/*
 * get a cacert with a given subject or keyid from an alternative list
 */
static const x509cert_t*
get_alt_cacert(chunk_t subject, chunk_t serial, chunk_t keyid
    , const x509cert_t *cert)
{
    while (cert != NULL)
    {
	if ((keyid.ptr != NULL) ? same_keyid(keyid, cert->subjectKeyID)
	    : (same_dn(subject, cert->subject)
	       && same_serial(serial, cert->serialNumber)))
	{
	    return cert;
	}
	cert = cert->next;
    }
    return NULL;
}

/* establish trust into a candidate authcert by going up the trust chain.
 * validity and revocation status are not checked.
 */
bool
trust_authcert_candidate(const x509cert_t *cert, const x509cert_t *alt_chain)
{
    int pathlen;

    lock_authcert_list("trust_authcert_candidate");

    for (pathlen = 0; pathlen < MAX_CA_PATH_LEN; pathlen++)
    {
	const x509cert_t *authcert = NULL;
	u_char buf[BUF_LEN];

	DBG(DBG_CONTROL,
	    dntoa(buf, BUF_LEN, cert->subject);
	    DBG_log("subject: '%s'",buf);
	    dntoa(buf, BUF_LEN, cert->issuer);
	    DBG_log("issuer:  '%s'",buf);
	    if (cert->authKeyID.ptr != NULL)
	    {
		datatot(cert->authKeyID.ptr, cert->authKeyID.len, ':'
		    , buf, BUF_LEN);
		DBG_log("authkey:  %s", buf);
	    }
	)

	/* search in alternative chain first */
	authcert = get_alt_cacert(cert->issuer, cert->authKeySerialNumber
	    , cert->authKeyID, alt_chain);

	if (authcert != NULL)
	{
	    DBG(DBG_CONTROL,
		DBG_log("issuer cacert found in alternative chain")
	    )
	}
	else
	{
	    /* search in trusted chain */
	    authcert = get_authcert(cert->issuer, cert->authKeySerialNumber
		, cert->authKeyID, AUTH_CA);

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

	if (!check_signature(cert->tbsCertificate, cert->signature
			   , cert->algorithm, cert->algorithm, authcert))
	{
	    plog("certificate signature is invalid");
	    unlock_authcert_list("trust_authcert_candidate");
	    return FALSE;
	}
	DBG(DBG_CONTROL,
	    DBG_log("certificate signature is valid")
	)

	/* check if cert is a self-signed root ca */
	if (pathlen > 0 && same_dn(cert->issuer, cert->subject))
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
ca_info_t*
get_ca_info(chunk_t authname, chunk_t serial, chunk_t keyid)
{
    ca_info_t *ca= ca_infos;

    while (ca!= NULL)
    {
	if ((keyid.ptr != NULL) ? same_keyid(keyid, ca->authKeyID)
	    : (same_dn(authname, ca->authName)
	       && same_serial(serial, ca->authKeySerialNumber)))
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
	return;

    free(ca_info->name);
    free(ca_info->ldaphost);
    free(ca_info->ldapbase);
    free(ca_info->ocspuri);
    free(ca_info->authName.ptr);
    free(ca_info->authKeyID.ptr);
    free(ca_info->authKeySerialNumber.ptr);
    free_generalNames(ca_info->crluri, TRUE);
    free(ca_info);
}

/*
 *  free  all CA certificates
 */
void
free_ca_infos(void)
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
bool
find_ca_info_by_name(const char *name, bool delete)
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
 * adds a CA description to a chained list
 */
void
add_ca_info(const whack_message_t *msg)
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
	char buf[BUF_LEN];
	x509cert_t *cacert = cert.u.x509;
	ca_info_t *ca = NULL;

	/* does the authname already exist? */
	ca = get_ca_info(cacert->subject, cacert->serialNumber
		, cacert->subjectKeyID);
	
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
	ca = malloc_thing(ca_info_t);
	*ca = empty_ca_info;

	/* name */
	ca->name = clone_str(msg->name);
	    
	/* authName */
	ca->authName = chunk_clone(cacert->subject);
	dntoa(buf, BUF_LEN, ca->authName);
	DBG(DBG_CONTROL,
	    DBG_log("authname: '%s'", buf)
	)

	/* authSerialNumber */
	ca->authKeySerialNumber = chunk_clone(cacert->serialNumber);

	/* authKeyID */
	if (cacert->subjectKeyID.ptr != NULL)
	{
	    ca->authKeyID = chunk_clone(cacert->subjectKeyID);
	    datatot(cacert->subjectKeyID.ptr, cacert->subjectKeyID.len, ':'
		, buf, BUF_LEN);
	    DBG(DBG_CONTROL | DBG_PARSING ,
		DBG_log("authkey:  %s", buf)
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

	/* crluri2*/
	if (msg->crluri2 != NULL)
	{
	    generalName_t gn =
		{ NULL, GN_URI, {msg->crluri2, strlen(msg->crluri2)} };

	    add_distribution_points(&gn, &ca->crluri);
	}

	/* crluri */
	if (msg->crluri != NULL)
	{
	    generalName_t gn =
		{ NULL, GN_URI, {msg->crluri, strlen(msg->crluri)} };

	    add_distribution_points(&gn, &ca->crluri);
	}

	/* strictrlpolicy */
	ca->strictcrlpolicy = msg->whack_strict;

	/* insert ca_info record into the chained list */
	lock_ca_info_list("add_ca_info");

	ca->next = ca_infos;
	ca_infos = ca;
	ca->installed = time(NULL);
	
	unlock_ca_info_list("add_ca_info");

	/* add cacert to list of authcerts */
	if (!cached_cert && sc != NULL)
	{
	    if (sc->last_cert.type == CERT_X509_SIGNATURE)
		sc->last_cert.u.x509->count--;
	    sc->last_cert.u.x509 = add_authcert(cacert, AUTH_CA);
	    share_cert(sc->last_cert);
	}
	if (sc != NULL)
	    time(&sc->last_load);
    }
}

/*
 * list all ca_info records in the chained list
 */
void
list_ca_infos(bool utc)
{
    ca_info_t *ca = ca_infos;
    
    if (ca != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of X.509 CA Information Records:");
	whack_log(RC_COMMENT, " ");
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
	whack_log(RC_COMMENT, "%T, \"%s\"", &ca->installed, utc, ca->name);
	dntoa(buf, BUF_LEN, ca->authName);
	whack_log(RC_COMMENT, "       authname: '%s'", buf);
	if (ca->ldaphost != NULL)
	    whack_log(RC_COMMENT, "       ldaphost: '%s'", ca->ldaphost);
	if (ca->ldapbase != NULL)
	    whack_log(RC_COMMENT, "       ldapbase: '%s'", ca->ldapbase);
	if (ca->ocspuri != NULL)
	    whack_log(RC_COMMENT, "       ocspuri:  '%s'", ca->ocspuri);

	list_distribution_points(ca->crluri);

	if (ca->authKeyID.ptr != NULL)
	{
	    datatot(ca->authKeyID.ptr, ca->authKeyID.len, ':'
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       authkey:   %s", buf);
	}
	if (ca->authKeySerialNumber.ptr != NULL)
	{
	    datatot(ca->authKeySerialNumber.ptr, ca->authKeySerialNumber.len, ':'
		, buf, BUF_LEN);
	    whack_log(RC_COMMENT, "       aserial:   %s", buf);
	}
	ca = ca->next;
    }
}


