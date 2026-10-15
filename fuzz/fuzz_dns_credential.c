/*
 * Copyright (C) 2026 Arthur SC Chan
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

#include <library.h>
#include <utils/debug.h>
#include <resolver/rr.h>
#include <plugins/dnscert/dnscert.h>
#include <plugins/ipseckey/ipseckey.h>

typedef struct fuzz_rr_t fuzz_rr_t;

struct fuzz_rr_t {
	rr_t public;
	char *name;
	rr_type_t type;
	rr_class_t class;
	uint32_t ttl;
	chunk_t rdata;
};

METHOD(rr_t, get_name, char*,
	fuzz_rr_t *this)
{
	return this->name;
}

METHOD(rr_t, get_type, rr_type_t,
	fuzz_rr_t *this)
{
	return this->type;
}

METHOD(rr_t, get_class, rr_class_t,
	fuzz_rr_t *this)
{
	return this->class;
}

METHOD(rr_t, get_ttl, uint32_t,
	fuzz_rr_t *this)
{
	return this->ttl;
}

METHOD(rr_t, get_rdata, chunk_t,
	fuzz_rr_t *this)
{
	return this->rdata;
}

METHOD(rr_t, rr_destroy, void,
	fuzz_rr_t *this)
{
	free(this);
}

static rr_t *fuzz_rr_create(rr_type_t type, chunk_t rdata)
{
	fuzz_rr_t *this;

	INIT(this,
		.public = {
			.get_name  = _get_name,
			.get_type  = _get_type,
			.get_class = _get_class,
			.get_ttl   = _get_ttl,
			.get_rdata = _get_rdata,
			.destroy   = _rr_destroy,
		},
		.name  = "fuzz.strongswan.org",
		.type  = type,
		.class = RR_CLASS_IN,
		.ttl   = 3600,
		.rdata = rdata,
	);
	return &this->public;
}

static const rr_type_t rr_types[] = {
	RR_TYPE_CERT,
	RR_TYPE_IPSECKEY,
	RR_TYPE_A,
	RR_TYPE_AAAA,
	RR_TYPE_SSHFP,
	RR_TYPE_DNSKEY,
	RR_TYPE_ANY,
	0,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_dns_credential");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	rr_t *rr;
	dnscert_t *dnscert;
	ipseckey_t *ipseckey;
	rr_type_t selected;
	chunk_t rdata;

	if (len < 4)
	{
		return 0;
	}

	selected = rr_types[buf[0] % countof(rr_types)];
	rdata = chunk_create((u_char*)buf + 1, len - 1);

	/* (1) Feed selected type to the dnscert parser. */
	rr = fuzz_rr_create(selected, rdata);
	dnscert = dnscert_create_frm_rr(rr);
	if (dnscert)
	{
		dnscert->get_cert_type(dnscert);
		dnscert->get_key_tag(dnscert);
		dnscert->get_algorithm(dnscert);
		dnscert->get_certificate(dnscert);
		dnscert->destroy(dnscert);
	}
	rr->destroy(rr);

	/* (2) Same selected type fed to the ipseckey parser */
	rr = fuzz_rr_create(selected, rdata);
	ipseckey = ipseckey_create_frm_rr(rr);
	if (ipseckey)
	{
		ipseckey->get_precedence(ipseckey);
		ipseckey->get_gateway_type(ipseckey);
		ipseckey->get_algorithm(ipseckey);
		ipseckey->get_gateway(ipseckey);
		ipseckey->get_public_key(ipseckey);
		ipseckey->destroy(ipseckey);
	}
	rr->destroy(rr);

	return 0;
}
