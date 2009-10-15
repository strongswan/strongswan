/* Support of X.509 attribute certificates
 * Copyright (C) 2002 Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2009 Andreas Steffen
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

#ifndef _AC_H
#define _AC_H

#include <utils/identification.h>
#include <credentials/certificates/certificate.h>
#include <credentials/ietf_attributes/ietf_attributes.h>

/* access structure for an X.509 attribute certificate */

extern void ac_initialize(void);
extern void ac_finalize(void);
extern void ac_load_certs(void);
extern void ac_list_certs(bool utc);

extern certificate_t* ac_get_cert(identification_t *issuer, chunk_t serial);

extern bool ac_verify_cert(certificate_t *ac, bool strict);

extern bool match_group_membership(ietf_attributes_t *peer_attributes,
								   char *conn,
								   ietf_attributes_t *conn_attributes);

#endif /* _AC_H */
