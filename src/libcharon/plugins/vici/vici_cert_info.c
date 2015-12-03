/*
 * Copyright (C) 2015 Andreas Steffen
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

#include "vici_cert_info.h"

static vici_cert_info_t vici_cert_infos[] = {
	{ "any", "",                                   CERT_ANY,
												   X509_NONE                },
	{ "x509", "X.509 End Entity Certificate",      CERT_X509,
												   X509_NONE                },
	{ "x509ca", "X.509 CA Certificate",            CERT_X509,
												   X509_CA                  },
	{ "x509aa", "X.509 AA Certificate",            CERT_X509,
												   X509_AA                  },
	{ "x509ocsp", "X.509 OCSP Signer Certificate", CERT_X509,
												   X509_OCSP_SIGNER         },
	{ "x509ac", "X.509 Attribute Certificate",     CERT_X509_AC,
												   X509_NONE                },
	{ "x509crl", "X.509 CRL",                      CERT_X509_CRL,
											 	   X509_NONE                },
	{ "ocsp", "OCSP Response",                     CERT_X509_OCSP_RESPONSE,
												   X509_NONE                }
};

/* See header. */
vici_cert_info_t* vici_cert_info_retrieve(char *type_str)
{
	int i;

	for (i = 0; i < countof(vici_cert_infos); i++)
	{
		if (strcaseeq(type_str, vici_cert_infos[i].type_str))
		{
			return &vici_cert_infos[i];
		}
	}
	return NULL;
}
