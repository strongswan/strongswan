/**
 * @file scep.h
 * @brief SCEP specific functions
 * 
 * Contains functions to build and parse SCEP requests and replies
 */
 
/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 */
 
#ifndef _SCEP_H
#define _SCEP_H

#include "../pluto/defs.h"
#include "../pluto/pkcs1.h"
#include "../pluto/pkcs7.h"

/* supported SCEP operation types */
typedef enum {
    SCEP_PKI_OPERATION,
    SCEP_GET_CA_CERT
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
   SCEP_PKCSReq_MSG,
   SCEP_GetCertInitial_MSG,
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

extern const scep_attributes_t empty_scep_attributes;

extern bool parse_attributes(chunk_t blob, scep_attributes_t *attrs);
extern void scep_generate_pkcs10_fingerprint(chunk_t pkcs10
    , chunk_t *fingerprint);
extern void scep_generate_transaction_id(const RSA_public_key_t *rsak
    , chunk_t *transID, chunk_t *serialNumber);
extern chunk_t scep_transId_attribute(chunk_t transaction_id);
extern chunk_t scep_messageType_attribute(scep_msg_t m);
extern chunk_t scep_senderNonce_attribute(void);
extern chunk_t scep_build_request(chunk_t data, chunk_t transID, scep_msg_t msg
    , const x509cert_t *enc_cert, int enc_alg
    , const x509cert_t *signer_cert, int digest_alg
    , const RSA_private_key_t *private_key);
extern bool scep_http_request(const char *url, chunk_t pkcs7, scep_op_t op
    , fetch_request_t request_type, chunk_t *response);
extern err_t scep_parse_response(chunk_t response, chunk_t transID
    , contentInfo_t *data, scep_attributes_t *attrs, x509cert_t *signer_cert);

#endif /* _SCEP_H */
