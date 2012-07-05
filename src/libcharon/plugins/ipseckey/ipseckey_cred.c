/*
 * Copyright (C) 2012 Reto Guadagnini
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
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "ipseckey_cred.h"
#include "ipseckey.h"

#include <bio/bio_reader.h>
#include <daemon.h>

typedef struct private_ipseckey_cred_t private_ipseckey_cred_t;

/**
 * Private data of an ipseckey_cred_t object
 */
struct private_ipseckey_cred_t {

	/**
	 * Public part
	 */
	ipseckey_cred_t public;

	/**
	 * DNS resolver
	 */
	resolver_t *res;
};

/**
 * enumerator over certificates
 */
typedef struct {
	/** implements enumerator interface */
	enumerator_t public;
	/** inner enumerator (enumerates IPSECKEY resource records) */
	enumerator_t *inner;
	/** response of the DNS resolver which contains the IPSECKEYs */
	resolver_response_t *response;
	/* IPSECKEYs are not valid before this point in time */
	time_t notBefore;
	/* IPSECKEYs are not valid after this point in time */
	time_t notAfter;
	/* identity to which the IPSECKEY belongs */
	identification_t *identity;
} cert_enumerator_t;

METHOD(enumerator_t, cert_enumerator_enumerate, bool,
	cert_enumerator_t *this, certificate_t **cert)
{
	rr_t *cur_rr = NULL;
	ipseckey_t *cur_ipseckey = NULL;
	chunk_t pub_key;
	public_key_t * key = NULL;
	bool supported_ipseckey_found = FALSE;

	DBG1(DBG_CFG, "ipseckey_cred: Enumerating over IPSECKEY certificates");

	/* Get the next supported IPSECKEY using the inner enumerator. */
	while (this->inner->enumerate(this->inner, &cur_rr) &&
		   !supported_ipseckey_found)
	{
		supported_ipseckey_found = TRUE;

		cur_ipseckey = ipseckey_create_frm_rr(cur_rr);

		if (!cur_ipseckey)
		{
			DBG1(DBG_CFG, "ipseckey_cred: Error while parsing an IPSECKEY. "
						  "Skipping this key");
			supported_ipseckey_found = FALSE;
		}

		if (cur_ipseckey &&
			cur_ipseckey->get_algorithm(cur_ipseckey) != IPSECKEY_ALGORITHM_RSA)
		{
			DBG1(DBG_CFG, "ipseckey_cred: Skipping an IPSECKEY which uses an "
						  "unsupported algorithm");
			cur_ipseckey->destroy(cur_ipseckey);
			supported_ipseckey_found = FALSE;
		}
	}

	if (supported_ipseckey_found)
	{
		/*
		 * Wrap the key of the IPSECKEY in a certificate and return this
		 * certificate.
		 */
		pub_key = cur_ipseckey->get_public_key(cur_ipseckey);

		key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
								 BUILD_BLOB_DNSKEY, pub_key,
								 BUILD_END);

		if (!key)
		{
			DBG1(DBG_CFG, "ipseckey_cred: Failed to create a public key "
						  "from the IPSECKEY");
			cur_ipseckey->destroy(cur_ipseckey);
			return FALSE;
		}

		*cert = lib->creds->create(lib->creds, CRED_CERTIFICATE,
								   CERT_TRUSTED_PUBKEY,
								   BUILD_PUBLIC_KEY, key,
								   BUILD_SUBJECT, this->identity,
								   BUILD_NOT_BEFORE_TIME, this->notBefore,
								   BUILD_NOT_AFTER_TIME, this->notAfter,
								   BUILD_END);
		return TRUE;
	}

	return FALSE;
}

METHOD(enumerator_t, cert_enumerator_destroy, void,
	cert_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	this->response->destroy(this->response);
	free(this);
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_ipseckey_cred_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	char *fqdn = NULL;
	resolver_response_t *response = NULL;
	rr_set_t *rrset = NULL;
	enumerator_t *rrsig_enum = NULL;
	rr_t *rrsig = NULL;
	bio_reader_t *reader = NULL;
	chunk_t ignore;
	u_int32_t nBefore, nAfter;
	cert_enumerator_t *e;

	if (id && id->get_type(id) == ID_FQDN)
	{
		/**	Query the DNS for the required IPSECKEY RRs */

		if (0 >= asprintf(&fqdn, "%Y", id))
		{
			DBG1(DBG_CFG, "ipseckey_cred: ID is empty");
			return enumerator_create_empty();
		}

		DBG1(DBG_CFG, "ipseckey_cred: Performing a DNS query for the IPSECKEY "
					  "RRs of the domain %s", fqdn);

		response = this->res->query(this->res, fqdn, RR_CLASS_IN,
									RR_TYPE_IPSECKEY);
		if (!response)
		{
			DBG1(DBG_CFG, "ipseckey_cred: DNS query failed");
			free(fqdn);
			return enumerator_create_empty();
		}

		if (!response->has_data(response) ||
			!response->query_name_exist(response))
		{
			DBG1(DBG_CFG, "ipseckey_cred: Unable to retrieve IPSECKEY RRs "
						  "for the domain %s from the DNS", fqdn);
			response->destroy(response);
			free(fqdn);
			return enumerator_create_empty();
		}

		if (!(response->get_security_state(response) == SECURE))
		{
			DBG1(DBG_CFG, "ipseckey_cred: DNSSEC security state of the "
						  "IPSECKEY RRs of the domain %s is not SECURE "
						  "as required", fqdn);
			response->destroy(response);
			free(fqdn);
			return enumerator_create_empty();
		}

		free(fqdn);

		/** Determine the validity period of the retrieved IPSECKEYs
		 *
		 * We use the "Signature Inception" and "Signature Expiration" field
		 * of the RRSIG resource record to determine the validity period of the
		 * IPSECKEY RRs.
		 */
		rrset = response->get_rr_set(response);
		rrsig_enum = rrset->create_rrsig_enumerator(rrset);
		if (!rrsig_enum)
		{
			DBG1(DBG_CFG, "ipseckey_cred: Unable to determine the validity "
						  "period of the RRs, because there are "
						  "no RRSIGs present");
			response->destroy(response);
			return enumerator_create_empty();
		}

		/**
		 * Currently we use the first RRSIG of the IPSECKEY RRset
		 * to determine the validity period of the IPSECKEYs.
		 * TODO: Take multiple RRSIGs into account.
		 */
		if (!rrsig_enum->enumerate(rrsig_enum, &rrsig))
		{
			DBG1(DBG_CFG, "ipseckey_cred: Unable to determine the validity "
						  "period of the IPSECKEY RRs, because there are "
						  "no RRSIGs present");
			rrsig_enum->destroy(rrsig_enum);
			response->destroy(response);
			return enumerator_create_empty();
		}

		/**
		 * Parse the RRSIG for its validity period.
		 * For the format of a RRSIG see RFC 4034.
		 */
		reader = bio_reader_create(rrsig->get_rdata(rrsig));
		reader->read_data(reader, 8, &ignore);
		reader->read_uint32(reader, &nAfter);
		reader->read_uint32(reader, &nBefore);
		reader->destroy(reader);

		/** Create and return an iterator over the retrieved IPSECKEYs */
		INIT(e,
			.public = {
				.enumerate = (void*)_cert_enumerator_enumerate,
				.destroy = _cert_enumerator_destroy,
			},
			.inner = response->get_rr_set(response)->create_rr_enumerator(
												response->get_rr_set(response)),
			.response = response,
			.notBefore = nBefore,
			.notAfter = nAfter,
			.identity = id,
		);

		return &e->public;
	}


	return enumerator_create_empty();
}

METHOD(ipseckey_cred_t, destroy, void,
	private_ipseckey_cred_t *this)
{
	this->res->destroy(this->res);
	free(this);
}

/**
 * Described in header.
 */
ipseckey_cred_t *ipseckey_cred_create(resolver_t *res)
{
	private_ipseckey_cred_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_private_enumerator = (void*)return_null,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_shared_enumerator = (void*)return_null,
				.create_cdp_enumerator = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
		.res = res,
	);

	return &this->public;
}
