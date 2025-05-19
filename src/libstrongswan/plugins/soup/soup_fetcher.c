/*
 * Copyright (C) 2010 Martin Willi
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

#include "soup_fetcher.h"

#include <libsoup/soup.h>

#include <library.h>
#include <utils/debug.h>

#define DEFAULT_TIMEOUT 10

typedef struct private_soup_fetcher_t private_soup_fetcher_t;

/**
 * private data of a soup_fetcher_t object.
 */
struct private_soup_fetcher_t {

	/**
	 * Public data
	 */
	soup_fetcher_t public;

	/**
	 * HTTP request method
	 */
	const char *method;

	/**
	 * Request content type
	 */
	char *type;

	/**
	 * Request data
	 */
	chunk_t data;

	/**
	 * Request timeout
	 */
	u_int timeout;

	/**
	 * Fetcher callback function
	 */
	fetcher_callback_t cb;

	/**
	 * Response status
	 */
	u_int *result;
};

/**
 * Data to pass to soup callback
 */
typedef struct {
	fetcher_callback_t cb;
	void *user;
	SoupSession *session;
	GCancellable *cancellable;
	GInputStream *stream;
} cb_data_t;

/**
 * Soup callback invoking our callback
 */
static void soup_cb(SoupMessage *message, guint chunk_size, cb_data_t *data)
{
	u_char *buf = (u_char *) malloc (chunk_size);
	if (!data->cb(data->user, chunk_create(buf, chunk_size)))
	{
		g_cancellable_cancel(data->cancellable);
	}
	free(buf);
}

METHOD(fetcher_t, fetch, status_t,
	private_soup_fetcher_t *this, char *uri, void *userdata)
{
	SoupMessage *message;
	status_t status = FAILED;
	GBytes *request_body;
	cb_data_t data = {
		.cb = this->cb,
		.user = userdata,
	};

	message = soup_message_new(this->method, uri);
	if (!message)
	{
		return NOT_SUPPORTED;
	}
	if (this->cb == fetcher_default_callback)
	{
		*(chunk_t*)userdata = chunk_empty;
	}
	if (this->type)
	{
		request_body = g_bytes_new_static(this->data.ptr, this->data.len);
		soup_message_set_request_body_from_bytes(message, this->type, request_body);
		g_bytes_unref(request_body);
	}
	g_signal_connect(message, "got-body-data", G_CALLBACK(soup_cb), &data);
	data.session = soup_session_new_with_options("timeout", (guint)this->timeout, NULL);
	data.cancellable = g_cancellable_new();

	DBG2(DBG_LIB, "sending http request to '%s'...", uri);
	data.stream = soup_session_send(data.session, message, data.cancellable, NULL);
	if (this->result)
	{
		*this->result = soup_message_get_status(message);
	}
	if (SOUP_STATUS_IS_SUCCESSFUL(soup_message_get_status(message)))
	{
		status = SUCCESS;
	}
	else if (!this->result)
	{	/* only log an error if the code is not returned */
		DBG1(DBG_LIB, "HTTP request failed: %s", soup_message_get_reason_phrase(message));
	}
	g_object_unref(data.stream);
	g_object_unref(G_OBJECT(message));
	g_object_unref(G_OBJECT(data.session));
	g_object_unref(data.cancellable);
	return status;
}

METHOD(fetcher_t, set_option, bool,
	private_soup_fetcher_t *this, fetcher_option_t option, ...)
{
	bool supported = TRUE;
	va_list args;

	va_start(args, option);
	switch (option)
	{
		case FETCH_REQUEST_DATA:
			this->method = SOUP_METHOD_POST;
			this->data = va_arg(args, chunk_t);
			break;
		case FETCH_REQUEST_TYPE:
			this->type = va_arg(args, char*);
			break;
		case FETCH_TIMEOUT:
			this->timeout = va_arg(args, u_int);
			break;
		case FETCH_CALLBACK:
			this->cb = va_arg(args, fetcher_callback_t);
			break;
		case FETCH_RESPONSE_CODE:
			this->result = va_arg(args, u_int*);
			break;
		default:
			supported = FALSE;
			break;
	}
	va_end(args);
	return supported;
}

METHOD(fetcher_t, destroy, void,
	private_soup_fetcher_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
soup_fetcher_t *soup_fetcher_create()
{
	private_soup_fetcher_t *this;

	INIT(this,
		.public = {
			.interface = {
				.fetch = _fetch,
				.set_option = _set_option,
				.destroy = _destroy,
			},
		},
		.method = SOUP_METHOD_GET,
		.timeout = DEFAULT_TIMEOUT,
		.cb = fetcher_default_callback,
	);

	return &this->public;
}
