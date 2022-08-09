/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2012 Tobias Brunner
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

#ifndef _SCEP_H
#define _SCEP_H

#include <credentials/containers/pkcs7.h>
#include <credentials/certificates/certificate.h>

/* supported SCEP operation types */
typedef enum {
	SCEP_PKI_OPERATION,
	SCEP_GET_CA_CERT,
	SCEP_GET_CA_CAPS
} scep_op_t;

/* SCEP pkiStatus values */
typedef enum {
	SCEP_SUCCESS,
	SCEP_FAILURE,
	SCEP_PENDING,
	SCEP_UNKNOWN
} pkiStatus_t;

/* SCEP messageType values */
typedef enum {
	SCEP_CertRep_MSG,
	SCEP_RenewalReq_MSG,
	SCEP_PKCSReq_MSG,
	SCEP_CertPoll_MSG,
	SCEP_GetCert_MSG,
	SCEP_GetCRL_MSG,
	SCEP_Unknown_MSG
} scep_msg_t;

/* SCEP failure reasons */
typedef enum {
	SCEP_badAlg_REASON =          0,
	SCEP_badMessageCheck_REASON = 1,
	SCEP_badRequest_REASON =      2,
	SCEP_badTime_REASON =         3,
	SCEP_badCertId_REASON =       4,
	SCEP_unknown_REASON =         5
} failInfo_t;

/* SCEP attributes */
typedef struct {
	scep_msg_t  msgType;
	pkiStatus_t pkiStatus;
	failInfo_t  failInfo;
	chunk_t     transID;
	chunk_t     senderNonce;
	chunk_t     recipientNonce;
} scep_attributes_t;

/* SCEP CA Capabilities */
typedef enum {
	SCEP_CAPS_AES =              0,
	SCEP_CAPS_DES3 =             1,
	SCEP_CAPS_SHA256 =           2,
	SCEP_CAPS_SHA384 =           3,
	SCEP_CAPS_SHA512 =           4,
	SCEP_CAPS_SHA224 =           5,
	SCEP_CAPS_SHA1 =             6,
	SCEP_CAPS_POSTPKIOPERATION = 7,
	SCEP_CAPS_SCEPSTANDARD =     8,
	SCEP_CAPS_GETNEXTCACERT =    9,
	SCEP_CAPS_RENEWAL =         10
} scep_caps_t;

extern const scep_attributes_t empty_scep_attributes;

bool parse_attributes(chunk_t blob, scep_attributes_t *attrs);

bool scep_generate_transaction_id(public_key_t *key,
								  chunk_t *transId, chunk_t *serialNumber);

chunk_t scep_transId_attribute(chunk_t transaction_id);

chunk_t scep_messageType_attribute(scep_msg_t m);

chunk_t scep_senderNonce_attribute(void);

chunk_t scep_build_request(chunk_t data, chunk_t transID, scep_msg_t msg,
						certificate_t *enc_cert, encryption_algorithm_t enc_alg,
						size_t key_size, certificate_t *signer_cert,
						hash_algorithm_t digest_alg, private_key_t *private_key);

bool scep_http_request(const char *url, chunk_t msg, scep_op_t op, bool use_post,
					   chunk_t *response);

bool scep_parse_response(chunk_t response, chunk_t transID, container_t **out,
						 scep_attributes_t *attrs);

uint32_t scep_parse_caps(chunk_t response);

#endif /* _SCEP_H */
