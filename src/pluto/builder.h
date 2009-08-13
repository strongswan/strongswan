/* Pluto certificate/CRL/AC builder hooks.
 * Copyright (C) 2009 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#ifndef _BUILDER_H
#define _BUILDER_H

/* types of pluto credentials */
typedef enum {
	/* cert_t certificate, either x509 or PGP */
	CRED_TYPE_CERTIFICATE,
	/* x509crl_t certificate revocation list */
	CRED_TYPE_CRL,
	/* x509acert_t attribute certificate */
	CRED_TYPE_AC,
} cred_type_t;

/* register credential builder hooks */
extern void init_builder();
/* unregister credential builder hooks */
extern void free_builder();

#endif /* _BUILDER_H */
