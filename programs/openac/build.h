/* Build a X.509 attribute certificate
 * Copyright (C) 2002  Ueli Galizzi, Ariane Seiler
 * Copyright (C) 2004  Andreas Steffen
 * Zuercher Hochschule Winterthur, Switzerland
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
 * RCSID $Id: build.h,v 1.4 2004/11/03 14:28:52 as Exp $
 */

#ifndef _BUILD_H
#define _BUILD_H

#include <time.h>

#include "../pluto/x509.h"
#include "../pluto/keys.h"
#include "../pluto/ac.h"

/*
 * global variables accessible by both main() and build.c
 */
extern x509cert_t *user;
extern x509cert_t *signer;

extern ietfAttrList_t *groups;
extern struct RSA_private_key *signerkey;

extern time_t notBefore;
extern time_t notAfter;

extern chunk_t serial;

/*
 * exported functions
 */
extern chunk_t build_attr_cert(void);

#endif /* _BUILD_H */
