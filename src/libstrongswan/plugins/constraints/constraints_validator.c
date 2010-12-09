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
	if (pathlen_constraint != X509_NO_PATH_LEN_CONSTRAINT &&
		pathlen > pathlen_constraint)
	{
		DBG1(DBG_CFG, "path length of %d violates constraint of %d",
			 pathlen, pathlen_constraint);
		return FALSE;
	}
	return TRUE;
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
