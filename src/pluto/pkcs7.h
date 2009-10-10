/* Support of PKCS#7 data structures
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2002-2009 Andreas Steffen
 *
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#ifndef _PKCS7_H
#define _PKCS7_H

#include <utils/linked_list.h>
#include <crypto/crypters/crypter.h>
#include <credentials/keys/private_key.h>
#include <credentials/certificates/certificate.h>

/* Access structure for a PKCS#7 ContentInfo object */

typedef struct contentInfo contentInfo_t;

struct contentInfo {
	int     type;
	chunk_t content;
};

extern const contentInfo_t empty_contentInfo;

extern bool pkcs7_parse_contentInfo(chunk_t blob, u_int level0,
									contentInfo_t *cInfo);
extern bool pkcs7_parse_signedData(chunk_t blob, contentInfo_t *data,
								   linked_list_t *cert, chunk_t *attributes,
								   certificate_t *cacert);
extern bool pkcs7_parse_envelopedData(chunk_t blob, chunk_t *data,
									  chunk_t serialNumber, private_key_t *key);
extern chunk_t pkcs7_contentType_attribute(void);
extern chunk_t pkcs7_messageDigest_attribute(chunk_t content, int digest_alg);
extern chunk_t pkcs7_build_issuerAndSerialNumber(certificate_t *cert);
extern chunk_t pkcs7_build_signedData(chunk_t data, chunk_t attributes,
									  certificate_t *cert, int digest_alg,
									  private_key_t *key);
extern chunk_t pkcs7_build_envelopedData(chunk_t data, certificate_t *cert,
										 int enc_alg);

#endif /* _PKCS7_H */
