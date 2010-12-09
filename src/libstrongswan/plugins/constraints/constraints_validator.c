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

METHOD(cert_validator_t, validate, bool,
	private_constraints_validator_t *this, certificate_t *subject,
	certificate_t *issuer, bool online, int pathlen, auth_cfg_t *auth)
{
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
