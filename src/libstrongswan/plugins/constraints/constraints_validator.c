/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "constraints_validator.h"

#include <debug.h>
#include <asn1/asn1.h>
#include <credentials/certificates/x509.h>

typedef struct private_constraints_validator_t private_constraints_validator_t;

/**
 * Private data of an constraints_validator_t object.
 */
struct private_constraints_validator_t {

	/**
	 * Public constraints_validator_t interface.
	 */
	constraints_validator_t public;
};

/**
 * Check pathlen constraint of issuer certificate
 */
static bool check_pathlen(x509_t *issuer, int pathlen)
{
	int pathlen_constraint;

	pathlen_constraint = issuer->get_pathLenConstraint(issuer);
	if (pathlen_constraint != X509_NO_CONSTRAINT &&
		pathlen > pathlen_constraint)
	{
		DBG1(DBG_CFG, "path length of %d violates constraint of %d",
			 pathlen, pathlen_constraint);
		return FALSE;
	}
	return TRUE;
}

/**
 * Check if a FQDN/RFC822 constraint matches (suffix match)
 */
static bool suffix_matches(identification_t *constraint, identification_t *id)
{
	chunk_t c, i;

	c = constraint->get_encoding(constraint);
	i = id->get_encoding(id);

	return i.len >= c.len && chunk_equals(c, chunk_skip(i, i.len - c.len));
}

/**
 * Check if a DN constraint matches (RDN prefix match)
 */
static bool dn_matches(identification_t *constraint, identification_t *id)
{
	enumerator_t *ec, *ei;
	id_part_t pc, pi;
	chunk_t cc, ci;
	bool match = TRUE;

	ec = constraint->create_part_enumerator(constraint);
	ei = id->create_part_enumerator(id);
	while (ec->enumerate(ec, &pc, &cc))
	{
		if (!ei->enumerate(ei, &pi, &ci) ||
			pi != pc || !chunk_equals(cc, ci))
		{
			match = FALSE;
			break;
		}
	}
	ec->destroy(ec);
	ei->destroy(ei);

	return match;
}

/**
 * Check if a certificate matches to a NameConstraint
 */
static bool name_constraint_matches(identification_t *constraint,
									certificate_t *cert, bool permitted)
{
	x509_t *x509 = (x509_t*)cert;
	enumerator_t *enumerator;
	identification_t *id;
	id_type_t type;
	bool matches = permitted;

	type = constraint->get_type(constraint);
	if (type == ID_DER_ASN1_DN)
	{
		matches = dn_matches(constraint, cert->get_subject(cert));
		if (matches != permitted)
		{
			return matches;
		}
	}

	enumerator = x509->create_subjectAltName_enumerator(x509);
	while (enumerator->enumerate(enumerator, &id))
	{
		if (id->get_type(id) == type)
		{
			switch (type)
			{
				case ID_FQDN:
				case ID_RFC822_ADDR:
					matches = suffix_matches(constraint, id);
					break;
				case ID_DER_ASN1_DN:
					matches = dn_matches(constraint, id);
					break;
				default:
					DBG1(DBG_CFG, "%N NameConstraint matching not implemented",
						 id_type_names, type);
					matches = FALSE;
					break;
			}
		}
		if (matches != permitted)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);

	return matches;
}

/**
 * Check if a permitted or excluded NameConstraint has been inherited to sub-CA
 */
static bool name_constraint_inherited(identification_t *constraint,
									  x509_t *x509, bool permitted)
{
	enumerator_t *enumerator;
	identification_t *id;
	bool inherited = FALSE;
	id_type_t type;

	if (!(x509->get_flags(x509) & X509_CA))
	{	/* not a sub-CA, not required */
		return TRUE;
	}

	type = constraint->get_type(constraint);
	enumerator = x509->create_name_constraint_enumerator(x509, permitted);
	while (enumerator->enumerate(enumerator, &id))
	{
		if (id->get_type(id) == type)
		{
			switch (type)
			{
				case ID_FQDN:
				case ID_RFC822_ADDR:
					if (permitted)
					{	/* permitted constraint can be narrowed */
						inherited = suffix_matches(constraint, id);
					}
					else
					{	/* excluded constraint can be widened */
						inherited = suffix_matches(id, constraint);
					}
					break;
				case ID_DER_ASN1_DN:
					if (permitted)
					{
						inherited = dn_matches(constraint, id);
					}
					else
					{
						inherited = dn_matches(id, constraint);
					}
					break;
				default:
					DBG1(DBG_CFG, "%N NameConstraint matching not implemented",
						 id_type_names, type);
					inherited = FALSE;
					break;
			}
		}
		if (inherited)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return inherited;
}

/**
 * Check name constraints
 */
static bool check_name_constraints(certificate_t *subject, x509_t *issuer)
{
	enumerator_t *enumerator;
	identification_t *constraint;

	enumerator = issuer->create_name_constraint_enumerator(issuer, TRUE);
	while (enumerator->enumerate(enumerator, &constraint))
	{
		if (!name_constraint_matches(constraint, subject, TRUE))
		{
			DBG1(DBG_CFG, "certificate '%Y' does not match permitted name "
				 "constraint '%Y'", subject->get_subject(subject), constraint);
			enumerator->destroy(enumerator);
			return FALSE;
		}
		if (!name_constraint_inherited(constraint, (x509_t*)subject, TRUE))
		{
			DBG1(DBG_CFG, "intermediate CA '%Y' does not inherit permitted name "
				 "constraint '%Y'", subject->get_subject(subject), constraint);
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);

	enumerator = issuer->create_name_constraint_enumerator(issuer, FALSE);
	while (enumerator->enumerate(enumerator, &constraint))
	{
		if (name_constraint_matches(constraint, subject, FALSE))
		{
			DBG1(DBG_CFG, "certificate '%Y' matches excluded name "
				 "constraint '%Y'", subject->get_subject(subject), constraint);
			enumerator->destroy(enumerator);
			return FALSE;
		}
		if (!name_constraint_inherited(constraint, (x509_t*)subject, FALSE))
		{
			DBG1(DBG_CFG, "intermediate CA '%Y' does not inherit excluded name "
				 "constraint '%Y'", subject->get_subject(subject), constraint);
			enumerator->destroy(enumerator);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * Check certificatePolicies
 */
static bool check_policy(x509_t *subject, x509_t *issuer, auth_cfg_t *auth)
{
	chunk_t any_policy = chunk_from_chars(0x55,0x1d,0x20,0x00);
	certificate_t *cert = (certificate_t*)issuer;
	enumerator_t *spols, *ipols;
	x509_cert_policy_t *spol, *ipol;
	bool found = TRUE;
	char *oid;

	spols = subject->create_cert_policy_enumerator(subject);
	while (spols->enumerate(spols, &spol))
	{
		found = FALSE;
		ipols = issuer->create_cert_policy_enumerator(issuer);
		while (ipols->enumerate(ipols, &ipol))
		{
			if (chunk_equals(spol->oid, ipol->oid) ||
				chunk_equals(ipol->oid, any_policy))
			{
				found = TRUE;
				break;
			}
		}
		ipols->destroy(ipols);
		if (!found)
		{
			oid = asn1_oid_to_string(spol->oid);
			DBG1(DBG_CFG, "policy %s missing in issuing certificate '%Y'",
				 oid, cert->get_subject(cert));
			free(oid);
			break;
		}
		if (auth)
		{
			oid = asn1_oid_to_string(spol->oid);
			if (oid)
			{
				auth->add(auth, AUTH_RULE_CERT_POLICY, oid);
			}
		}
	}
	spols->destroy(spols);

	return found;
}

METHOD(cert_validator_t, validate, bool,
	private_constraints_validator_t *this, certificate_t *subject,
	certificate_t *issuer, bool online, int pathlen, auth_cfg_t *auth)
{
	if (issuer->get_type(issuer) == CERT_X509 &&
		subject->get_type(subject) == CERT_X509)
	{
		if (!check_pathlen((x509_t*)issuer, pathlen))
		{
			return FALSE;
		}
		if (!check_name_constraints(subject, (x509_t*)issuer))
		{
			return FALSE;
		}
		if (!check_policy((x509_t*)subject, (x509_t*)issuer, auth))
		{
			return FALSE;
		}
	}
	return TRUE;
}

METHOD(constraints_validator_t, destroy, void,
	private_constraints_validator_t *this)
{
	free(this);
}

/**
 * See header
 */
constraints_validator_t *constraints_validator_create()
{
	private_constraints_validator_t *this;

	INIT(this,
		.public = {
			.validator.validate = _validate,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
