/*
 * Copyright (C) 2015 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "certificate_printer.h"
#include "x509.h"
#include "crl.h"
#include "ac.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <selectors/traffic_selector.h>

#include <time.h>

typedef struct private_certificate_printer_t private_certificate_printer_t;

/**
 * Private data of an certificate_printer_t object.
 */
struct private_certificate_printer_t {

	/**
	 * Public certificate_printer_t interface.
	 */
	certificate_printer_t public;

	/**
	 * File to print to
	 */
	FILE *f;

	/**
	 * Print detailed certificate information
	 */
	bool detailed;

	/**
	 * Print time information in UTC
	 */
	bool utc;
};

/**
 * Print X509 specific certificate information
 */
static void print_x509(private_certificate_printer_t *this, x509_t *x509)
{
	enumerator_t *enumerator;
	identification_t *id;
	traffic_selector_t *block;
	chunk_t chunk;
	bool first;
	char *uri;
	int len, explicit, inhibit;
	x509_flag_t flags;
	x509_cdp_t *cdp;
	x509_cert_policy_t *policy;
	x509_policy_mapping_t *mapping;
	FILE *f = this->f;

	chunk = chunk_skip_zero(x509->get_serial(x509));
	fprintf(f, "  serial:    %#B\n", &chunk);

	first = TRUE;
	enumerator = x509->create_subjectAltName_enumerator(x509);
	while (enumerator->enumerate(enumerator, &id))
	{
		if (first)
		{
			fprintf(f, "  altNames:  ");
			first = FALSE;
		}
		else
		{
			fprintf(f, ", ");
		}
		fprintf(f, "%Y", id);
	}
	if (!first)
	{
		fprintf(f, "\n");
	}
	enumerator->destroy(enumerator);

	if (this->detailed)
	{
		flags = x509->get_flags(x509);
		if (flags != X509_NONE)
		{
			fprintf(f, "  flags:     ");
			if (flags & X509_CA)
			{
				fprintf(f, "CA ");
			}
			if (flags & X509_CRL_SIGN)
			{
				fprintf(f, "CRLSign ");
			}
			if (flags & X509_OCSP_SIGNER)
			{
				fprintf(f, "ocspSigning ");
			}
			if (flags & X509_SERVER_AUTH)
			{
				fprintf(f, "serverAuth ");
			}
			if (flags & X509_CLIENT_AUTH)
			{
				fprintf(f, "clientAuth ");
			}
			if (flags & X509_IKE_INTERMEDIATE)
			{
				fprintf(f, "ikeIntermediate ");
			}
			if (flags & X509_MS_SMARTCARD_LOGON)
			{
				fprintf(f, "msSmartcardLogon");
			}
			if (flags & X509_SELF_SIGNED)
			{
				fprintf(f, "self-signed ");
			}
			fprintf(f, "\n");
		}

		first = TRUE;
		enumerator = x509->create_crl_uri_enumerator(x509);
		while (enumerator->enumerate(enumerator, &cdp))
		{
			if (first)
			{
				fprintf(f, "  CRL URIs:  %s", cdp->uri);
				first = FALSE;
			}
			else
			{
				fprintf(f, "           %s", cdp->uri);
			}
			if (cdp->issuer)
			{
				fprintf(f, " (CRL issuer: %Y)", cdp->issuer);
			}
			fprintf(f, "\n");
		}
		enumerator->destroy(enumerator);

		first = TRUE;
		enumerator = x509->create_ocsp_uri_enumerator(x509);
		while (enumerator->enumerate(enumerator, &uri))
		{
			if (first)
			{
				fprintf(f, "  OCSP URIs: %s\n", uri);
				first = FALSE;
			}
			else
			{
				fprintf(f, "           %s\n", uri);
			}
		}
		enumerator->destroy(enumerator);

		len = x509->get_constraint(x509, X509_PATH_LEN);
		if (len != X509_NO_CONSTRAINT)
		{
			fprintf(f, "  pathlen:   %d\n", len);
		}

		first = TRUE;
		enumerator = x509->create_name_constraint_enumerator(x509, TRUE);
		while (enumerator->enumerate(enumerator, &id))
		{
			if (first)
			{
				fprintf(f, "  permitted nameConstraints:\n");
				first = FALSE;
			}
			fprintf(f, "           %Y\n", id);
		}
		enumerator->destroy(enumerator);

		first = TRUE;
		enumerator = x509->create_name_constraint_enumerator(x509, FALSE);
		while (enumerator->enumerate(enumerator, &id))
		{
			if (first)
			{
				fprintf(f, "  excluded nameConstraints:\n");
				first = FALSE;
			}
			fprintf(f, "           %Y\n", id);
		}
		enumerator->destroy(enumerator);

		first = TRUE;
		enumerator = x509->create_cert_policy_enumerator(x509);
		while (enumerator->enumerate(enumerator, &policy))
		{
			char *oid;

			if (first)
			{
				fprintf(f, "  certificatePolicies:\n");
				first = FALSE;
			}
			oid = asn1_oid_to_string(policy->oid);
			if (oid)
			{
				fprintf(f, "             %s\n", oid);
				free(oid);
			}
			else
			{
				fprintf(f, "             %#B\n", &policy->oid);
			}
			if (policy->cps_uri)
			{
				fprintf(f, "             CPS: %s\n", policy->cps_uri);
			}
			if (policy->unotice_text)
			{
				fprintf(f, "             Notice: %s\n", policy->unotice_text);
			}
		}
		enumerator->destroy(enumerator);

		first = TRUE;
		enumerator = x509->create_policy_mapping_enumerator(x509);
		while (enumerator->enumerate(enumerator, &mapping))
		{
			char *issuer_oid, *subject_oid;

			if (first)
			{
				fprintf(f, "  policyMappings:\n");
				first = FALSE;
			}
			issuer_oid = asn1_oid_to_string(mapping->issuer);
			subject_oid = asn1_oid_to_string(mapping->subject);
			fprintf(f, "           %s => %s\n", issuer_oid, subject_oid);
			free(issuer_oid);
			free(subject_oid);
		}
		enumerator->destroy(enumerator);

		explicit = x509->get_constraint(x509, X509_REQUIRE_EXPLICIT_POLICY);
		inhibit = x509->get_constraint(x509, X509_INHIBIT_POLICY_MAPPING);
		len = x509->get_constraint(x509, X509_INHIBIT_ANY_POLICY);

		if (explicit != X509_NO_CONSTRAINT || inhibit != X509_NO_CONSTRAINT ||
			len != X509_NO_CONSTRAINT)
		{
			fprintf(f, "  policyConstraints:\n");
			if (explicit != X509_NO_CONSTRAINT)
			{
				fprintf(f, "           requireExplicitPolicy: %d\n", explicit);
			}
			if (inhibit != X509_NO_CONSTRAINT)
			{
				fprintf(f, "           inhibitPolicyMapping: %d\n", inhibit);
			}
			if (len != X509_NO_CONSTRAINT)
			{
				fprintf(f, "           inhibitAnyPolicy: %d\n", len);
			}
		}

		if (x509->get_flags(x509) & X509_IP_ADDR_BLOCKS)
		{
			first = TRUE;
			fprintf(f, "  addresses: ");
			enumerator = x509->create_ipAddrBlock_enumerator(x509);
			while (enumerator->enumerate(enumerator, &block))
			{
				if (first)
				{
					first = FALSE;
				}
				else
				{
					fprintf(f, ", ");
				}
				fprintf(f, "%R", block);
			}
			enumerator->destroy(enumerator);
			fprintf(f, "\n");
		}
	}

	chunk = x509->get_authKeyIdentifier(x509);
	if (chunk.ptr)
	{
		fprintf(f, "  authkeyId: %#B\n", &chunk);
	}

	chunk = x509->get_subjectKeyIdentifier(x509);
	if (chunk.ptr)
	{
		fprintf(f, "  subjkeyId: %#B\n", &chunk);
	}
}

/**
 * Print CRL specific information
 */
static void print_crl(private_certificate_printer_t *this, crl_t *crl)
{
	enumerator_t *enumerator;
	time_t ts;
	crl_reason_t reason;
	chunk_t chunk;
	int count = 0;
	bool first;
	char buf[64];
	x509_cdp_t *cdp;
	FILE *f = this->f;

	chunk = chunk_skip_zero(crl->get_serial(crl));
	fprintf(f, "  serial:    %#B\n", &chunk);

	if (crl->is_delta_crl(crl, &chunk))
	{
		chunk = chunk_skip_zero(chunk);
		fprintf(f, "  delta CRL: for serial %#B\n", &chunk);
	}
	chunk = crl->get_authKeyIdentifier(crl);
	fprintf(f, "  authKeyId: %#B\n", &chunk);

	first = TRUE;
	enumerator = crl->create_delta_crl_uri_enumerator(crl);
	while (enumerator->enumerate(enumerator, &cdp))
	{
		if (first)
		{
			fprintf(f, "  freshest:  %s", cdp->uri);
			first = FALSE;
		}
		else
		{
			fprintf(f, "             %s", cdp->uri);
		}
		if (cdp->issuer)
		{
			fprintf(f, " (CRL issuer: %Y)", cdp->issuer);
		}
		fprintf(f, "\n");
	}
	enumerator->destroy(enumerator);

	enumerator = crl->create_enumerator(crl);
	while (enumerator->enumerate(enumerator, &chunk, &ts, &reason))
	{
		count++;
	}
	enumerator->destroy(enumerator);

	fprintf(f, "  %d revoked certificate%s%s\n", count, (count == 1) ? "" : "s",
				(count && this->detailed) ? ":" : "");

	if (this->detailed)
	{
		enumerator = crl->create_enumerator(crl);
		while (enumerator->enumerate(enumerator, &chunk, &ts, &reason))
		{
			chunk = chunk_skip_zero(chunk);
			fprintf(f, "    %#B: %T, %N\n", &chunk, &ts, this->utc,
											crl_reason_names, reason);
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Print AC specific information
 */
static void print_ac(private_certificate_printer_t *this, ac_t *ac)
{
	ac_group_type_t type;
	identification_t *id;
	enumerator_t *groups;
	chunk_t chunk;
	bool first = TRUE;
	FILE *f = this->f;

	chunk = chunk_skip_zero(ac->get_serial(ac));
	fprintf(f, "  serial:    %#B\n", &chunk);

	id = ac->get_holderIssuer(ac);
	if (id)
	{
		fprintf(f, "  hissuer:  \"%Y\"\n", id);
	}
	chunk = chunk_skip_zero(ac->get_holderSerial(ac));
	if (chunk.ptr)
	{
		fprintf(f, "  hserial:   %#B\n", &chunk);
	}
	groups = ac->create_group_enumerator(ac);
	while (groups->enumerate(groups, &type, &chunk))
	{
		int oid;
		char *str;

		if (first)
		{
			fprintf(f, "  groups:    ");
			first = FALSE;
		}
		else
		{
			fprintf(f, "             ");
		}
		switch (type)
		{
			case AC_GROUP_TYPE_STRING:
				fprintf(f, "%.*s", (int)chunk.len, chunk.ptr);
				break;
			case AC_GROUP_TYPE_OID:
				oid = asn1_known_oid(chunk);
				if (oid == OID_UNKNOWN)
				{
					str = asn1_oid_to_string(chunk);
					if (str)
					{
						fprintf(f, "%s", str);
						free(str);
					}
					else
					{
						fprintf(f, "OID:%#B", &chunk);
					}
				}
				else
				{
					fprintf(f, "%s", oid_names[oid].name);
				}
				break;
			case AC_GROUP_TYPE_OCTETS:
				fprintf(f, "%#B", &chunk);
				break;
		}
		fprintf(f, "\n");
	}
	groups->destroy(groups);

	chunk = ac->get_authKeyIdentifier(ac);
	if (chunk.ptr)
	{
		fprintf(f, "  authkey:  %#B\n", &chunk);
	}
}

/**
 * Print public key information
 */
static void print_pubkey(private_certificate_printer_t *this, public_key_t *key,
						 bool has_privkey)
{
	chunk_t chunk;
	FILE *f = this->f;

	fprintf(f, "  pubkey:    %N %d bits", key_type_names, key->get_type(key),
				key->get_keysize(key));
	if (has_privkey)
	{
		fprintf(f, ", has private key");
	}
	fprintf(f, "\n");
	if (key->get_fingerprint(key, KEYID_PUBKEY_INFO_SHA1, &chunk))
	{
		fprintf(f, "  keyid:     %#B\n", &chunk);
	}
	if (key->get_fingerprint(key, KEYID_PUBKEY_SHA1, &chunk))
	{
		fprintf(f, "  subjkey:   %#B\n", &chunk);
	}
}

METHOD(certificate_printer_t, print, void,
	private_certificate_printer_t *this, certificate_t *cert, bool has_privkey)
{
	time_t now, notAfter, notBefore;
	certificate_type_t type;
	identification_t *subject;
	public_key_t *key;
	FILE *f = this->f;

	now = time(NULL);
	type = cert->get_type(cert);
	subject = cert->get_subject(cert);

	if ((type != CERT_X509_CRL && type != CERT_X509_OCSP_RESPONSE &&
		 type != CERT_TRUSTED_PUBKEY) ||
	    (type == CERT_TRUSTED_PUBKEY && subject->get_type(subject) != ID_KEY_ID))
	{
		fprintf(f, "  subject:  \"%Y\"\n", subject);
	}
	if (cert->get_type(cert) != CERT_TRUSTED_PUBKEY)
	{
		fprintf(f, "  issuer:   \"%Y\"\n", cert->get_issuer(cert));
	}

	/* list validity if set */
	cert->get_validity(cert, &now, &notBefore, &notAfter);
	if (notBefore != UNDEFINED_TIME && notAfter != UNDEFINED_TIME)
	{
		fprintf(f, "  validity:  not before %T, ", &notBefore, this->utc);
		if (now < notBefore)
		{
			fprintf(f, "not valid yet (valid in %V)\n", &now, &notBefore);
		}
		else
		{
			fprintf(f, "ok\n");
		}
		fprintf(f, "             not after  %T, ", &notAfter, this->utc);
		if (now > notAfter)
		{
			fprintf(f, "expired (%V ago)\n", &now, &notAfter);
		}
		else
		{
			fprintf(f, "ok (expires in %V)\n", &now, &notAfter);
		}
	}

	switch (cert->get_type(cert))
	{
		case CERT_X509:
			print_x509(this, (x509_t*)cert);
			break;
		case CERT_X509_CRL:
			print_crl(this, (crl_t*)cert);
			break;
		case CERT_X509_AC:
			print_ac(this, (ac_t*)cert);
			break;
		case CERT_X509_OCSP_RESPONSE:
		case CERT_TRUSTED_PUBKEY:
		default:
			break;
	}
	key = cert->get_public_key(cert);
	if (key)
	{
		print_pubkey(this, key, has_privkey);
		key->destroy(key);
	}
}

METHOD(certificate_printer_t, destroy, void,
	private_certificate_printer_t *this)
{
	free(this);
}

/**
 * See header
 */
certificate_printer_t *certificate_printer_create(FILE *f, bool detailed,
												  bool utc)
{
	private_certificate_printer_t *this;

	INIT(this,
		.public = {
			.print = _print,
			.destroy = _destroy,
		},
		.f = f,
		.detailed = detailed,
		.utc = utc,
	);

	return &this->public;
}
