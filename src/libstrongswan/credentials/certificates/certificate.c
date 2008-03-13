/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * $Id$
 */

#include "certificate.h"

#include <credentials/certificates/x509.h>

ENUM(certificate_type_names, CERT_ANY, CERT_PGP,
	"ANY",
	"X509",
	"X509_CRL",
	"X509_OCSP_REQUEST",
	"X509_OCSP_RESPONSE",
	"X509_AC",
	"X509_CHAIN",
	"TRUSTED_PUBKEY",
	"PGP",
);

ENUM(cert_validation_names, VALIDATION_GOOD, VALIDATION_SKIPPED,
	"GOOD",
	"REVOKED",
	"FAILED",
	"SKIPPED",
);

