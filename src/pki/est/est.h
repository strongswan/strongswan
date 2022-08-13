/*
 * Copyright (C) 2022 Andreas Steffen, strongSec GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

#ifndef _EST_H
#define _EST_H

#include <library.h>

/**
 * EST (RFC 7030) Operations
 */
typedef enum {
	EST_CACERTS,
	EST_SIMPLE_ENROLL,
	EST_SIMPLE_REENROLL,
	EST_FULL_CMC,
	EST_SERVER_KEYGEN,
	EST_CSR_ATTRS
} est_op_t;

/**
 * Send an EST request via HTTPS and wait for a response
 */
bool est_https_request(const char *url, est_op_t op, bool http_post,
					   chunk_t data, chunk_t *response, u_int *http_code);

#endif /* _EST_H */
