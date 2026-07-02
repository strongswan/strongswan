/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2007 Andreas Steffen
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

#define _GNU_SOURCE /* for asprintf() */

#include <ldap.h>

#include <library.h>
#include <utils/debug.h>

#include "ldap_fetcher.h"

#define DEFAULT_TIMEOUT 10

typedef struct private_ldap_fetcher_t private_ldap_fetcher_t;

/**
 * Private Data of a ldap_fetcher_t object.
 */
struct private_ldap_fetcher_t {
	/**
	 * Public data
	 */
	ldap_fetcher_t public;

	/**
	 * timeout to use for fetches
	 */
	u_int timeout;
};

/**
 * Parses the result returned by an ldap query
 */
static bool parse(LDAP *ldap, LDAPMessage *result, chunk_t *response)
{
	LDAPMessage *entry = ldap_first_entry(ldap, result);
	bool success = FALSE;
	int res = 0;

	if (entry)
	{
		BerElement *ber = NULL;
		char *attr;

		attr = ldap_first_attribute(ldap, entry, &ber);
		if (attr)
		{
			struct berval **values = ldap_get_values_len(ldap, entry, attr);

			if (values)
			{
				if (values[0])
				{
					*response = chunk_alloc(values[0]->bv_len);
					memcpy(response->ptr, values[0]->bv_val, response->len);
					success = TRUE;
				}
				else
				{
					DBG1(DBG_LIB, "LDAP response contains no values");
				}
				ldap_value_free_len(values);
			}
			else
			{
				ldap_get_option(ldap, LDAP_OPT_RESULT_CODE, &res);
				DBG1(DBG_LIB, "getting LDAP values failed: %s",
					 ldap_err2string(res));
			}
			ldap_memfree(attr);
		}
		else
		{
			ldap_get_option(ldap, LDAP_OPT_RESULT_CODE, &res);
			DBG1(DBG_LIB, "finding LDAP attributes failed: %s",
				 ldap_err2string(res));
		}
		ber_free(ber, 0);
	}
	else
	{
		DBG1(DBG_LIB, "finding first LDAP entry failed");
	}
	return success;
}

/**
 * Set an LDAP option and report the error if necessary
 */
static bool set_ldap_option(LDAP *ldap, int option, const void *value,
							const char *name)
{
	int res;

	res = ldap_set_option(ldap, option, value);
	if (res != LDAP_OPT_SUCCESS)
	{
		DBG1(DBG_LIB, "setting LDAP option '%s' failed: %s", name,
			 ldap_err2string(res));
		return FALSE;
	}
	return TRUE;
}

/**
 * Generate an URL accepted by ldap_initialize(), only consisting of scheme,
 * host and port.
 */
static char *build_ldap_url(LDAPURLDesc *lurl)
{
	char *url = NULL;
	bool ipv6;

	if (!lurl->lud_host || !*lurl->lud_host)
	{
		DBG1(DBG_LIB, "LDAP URL without host not supported");
		return NULL;
	}

	ipv6 = strchr(lurl->lud_host, ':') != NULL;
	if (lurl->lud_port)
	{
		if (asprintf(&url, ipv6 ? "%s://[%s]:%d" : "%s://%s:%d",
					 lurl->lud_scheme, lurl->lud_host, lurl->lud_port) < 0)
		{
			return NULL;
		}
	}
	else
	{
		if (asprintf(&url, ipv6 ? "%s://[%s]" : "%s://%s", lurl->lud_scheme,
					 lurl->lud_host) < 0)
		{
			return NULL;
		}
	}
	return url;
}

METHOD(fetcher_t, fetch, status_t,
	private_ldap_fetcher_t *this, char *url, void *userdata)
{
	LDAP *ldap = NULL;
	LDAPURLDesc *lurl;
	char *ldap_url;
	LDAPMessage *msg;
	chunk_t *result = userdata;
	struct timeval timeout;
	int ldap_version = LDAP_VERSION3;
	int res;
	struct berval cred = {0, ""};
	status_t status = FAILED;

	if (!strpfx(url, "ldap"))
	{
		return NOT_SUPPORTED;
	}
	if (ldap_url_parse(url, &lurl) != LDAP_SUCCESS)
	{
		return NOT_SUPPORTED;
	}
	if (!streq(lurl->lud_scheme, "ldap") && !streq(lurl->lud_scheme, "ldaps"))
	{
		ldap_free_urldesc(lurl);
		return NOT_SUPPORTED;
	}
	/* ldap_initialize() only expects "scheme://host:port", so we have to
	 * generate an appropriate string */
	ldap_url = build_ldap_url(lurl);
	if (!ldap_url)
	{
		ldap_free_urldesc(lurl);
		return FAILED;
	}
	res = ldap_initialize(&ldap, ldap_url);
	free(ldap_url);
	if (res != LDAP_SUCCESS)
	{
		DBG1(DBG_LIB, "LDAP initialization failed: %s", ldap_err2string(res));
		ldap_free_urldesc(lurl);
		return FAILED;
	}

	if (streq(lurl->lud_scheme, "ldaps"))
	{
		int require_cert = LDAP_OPT_X_TLS_DEMAND;

		if (!set_ldap_option(ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &require_cert,
							 "TLS require cert") ||
			!set_ldap_option(ldap, LDAP_OPT_X_TLS_NEWCTX, LDAP_OPT_ON,
							 "TLS context"))
		{
			ldap_unbind_ext_s(ldap, NULL, NULL);
			ldap_free_urldesc(lurl);
			return FAILED;
		}
	}

	timeout.tv_sec = this->timeout;
	timeout.tv_usec = 0;

	if (!set_ldap_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version,
						 "protocol version") ||
		!set_ldap_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout,
						 "network timeout") ||
		!set_ldap_option(ldap, LDAP_OPT_TIMEOUT, &timeout, "timeout"))
	{
		ldap_unbind_ext_s(ldap, NULL, NULL);
		ldap_free_urldesc(lurl);
		return FAILED;
	}

	DBG2(DBG_LIB, "sending LDAP request to '%s'...", url);

	res = ldap_sasl_bind_s(ldap, NULL, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (res == LDAP_SUCCESS)
	{
		res = ldap_search_ext_s(ldap, lurl->lud_dn, lurl->lud_scope,
								lurl->lud_filter, lurl->lud_attrs,
								0, NULL, NULL, &timeout, LDAP_NO_LIMIT, &msg);

		if (res == LDAP_SUCCESS)
		{
			if (parse(ldap, msg, result))
			{
				status = SUCCESS;
			}
			ldap_msgfree(msg);
		}
		else
		{
			DBG1(DBG_LIB, "LDAP search failed: %s", ldap_err2string(res));
		}
	}
	else
	{
		DBG1(DBG_LIB, "LDAP bind to '%s' failed: %s", url,
			 ldap_err2string(res));
	}
	ldap_unbind_ext_s(ldap, NULL, NULL);
	ldap_free_urldesc(lurl);
	return status;
}


METHOD(fetcher_t, set_option, bool,
	private_ldap_fetcher_t *this, fetcher_option_t option, ...)
{
	va_list args;

	va_start(args, option);
	switch (option)
	{
		case FETCH_TIMEOUT:
			this->timeout = va_arg(args, u_int);
			break;
		default:
			va_end(args);
			return FALSE;
	}
	va_end(args);
	return TRUE;
}

METHOD(fetcher_t, destroy, void,
	private_ldap_fetcher_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ldap_fetcher_t *ldap_fetcher_create()
{
	private_ldap_fetcher_t *this;

	INIT(this,
		.public = {
			.interface = {
				.fetch = _fetch,
				.set_option = _set_option,
				.destroy = _destroy,
			},
		},
		.timeout = DEFAULT_TIMEOUT,
	);

	return &this->public;
}
