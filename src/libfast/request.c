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
 */

#define _GNU_SOURCE

#include "request.h"

#include <library.h>
#include <debug.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <ClearSilver/ClearSilver.h>

#include <threading/thread.h>
#include <threading/thread_value.h>

typedef struct private_request_t private_request_t;

/**
 * private data of the task manager
 */
struct private_request_t {

	/**
	 * public functions
	 */
	request_t public;

	/**
	 * FastCGI request object
	 */
	FCGX_Request req;

	/**
	 * length of the req.envp array
	 */
	int req_env_len;

	/**
	 * ClearSilver CGI Kit context
	 */
	CGI *cgi;

	/**
	 * ClearSilver HDF dataset for this request
	 */
	HDF *hdf;

	/**
	 * close the session?
	 */
	bool closed;

	/**
	 * reference count
	 */
	refcount_t ref;
};

/**
 * ClearSilver cgiwrap is not threadsave, so we use a private
 * context for each thread.
 */
static thread_value_t *thread_this;

/**
 * control variable for pthread_once
 */
pthread_once_t once = PTHREAD_ONCE_INIT;

/**
 * fcgiwrap read callback
 */
static int read_cb(void *null, char *buf, int size)
{
	private_request_t *this = (private_request_t*)thread_this->get(thread_this);

	return FCGX_GetStr(buf, size, this->req.in);
}

/**
 * fcgiwrap writef callback
 */
static int writef_cb(void *null, const char *format, va_list args)
{
	private_request_t *this = (private_request_t*)thread_this->get(thread_this);

	FCGX_VFPrintF(this->req.out, format, args);
	return 0;
}
/**
 * fcgiwrap write callback
 */
static int write_cb(void *null, const char *buf, int size)
{
	private_request_t *this = (private_request_t*)thread_this->get(thread_this);

	return FCGX_PutStr(buf, size, this->req.out);
}

/**
 * fcgiwrap getenv callback
 */
static char *getenv_cb(void *null, const char *key)
{
	char *value;
	private_request_t *this = (private_request_t*)thread_this->get(thread_this);

	value = FCGX_GetParam(key, this->req.envp);
	return value ? strdup(value) : NULL;
}

/**
 * fcgiwrap getenv callback
 */
static int putenv_cb(void *null, const char *key, const char *value)
{
	/* not supported */
	return 1;
}

/**
 * fcgiwrap iterenv callback
 */
static int iterenv_cb(void *null, int num, char **key, char **value)
{
	*key = NULL;
	*value = NULL;
	private_request_t *this = (private_request_t*)thread_this->get(thread_this);
	if (num < this->req_env_len)
	{
		char *eq;

		eq = strchr(this->req.envp[num], '=');
		if (eq)
		{
			*key = strndup(this->req.envp[num], eq - this->req.envp[num]);
			*value = strdup(eq + 1);
		}
		if (*key == NULL || *value == NULL)
		{
			free(*key);
			free(*value);
			return 1;
		}
	}
	return 0;
}

/**
 * Implementation of request_t.get_cookie.
 */
static char* get_cookie(private_request_t *this, char *name)
{
	return hdf_get_valuef(this->hdf, "Cookie.%s", name);
}

/**
 * Implementation of request_t.get_path.
 */
static char* get_path(private_request_t *this)
{
	char * path = FCGX_GetParam("PATH_INFO", this->req.envp);
	return path ? path : "";
}

/**
 * Implementation of request_t.get_host.
 */
static char* get_host(private_request_t *this)
{
	char *addr = FCGX_GetParam("REMOTE_ADDR", this->req.envp);
	return addr ? addr : "";
}

/**
 * Implementation of request_t.get_user_agent.
 */
static char* get_user_agent(private_request_t *this)
{
	char *agent = FCGX_GetParam("HTTP_USER_AGENT", this->req.envp);
	return agent ? agent : "";
}

/**
 * Implementation of request_t.get_post_data.
 */
static char* get_query_data(private_request_t *this, char *name)
{
	return hdf_get_valuef(this->hdf, "Query.%s", name);
}

/**
 * Implementation of request_t.add_cookie.
 */
static void add_cookie(private_request_t *this, char *name, char *value)
{
	thread_this->set(thread_this, this);
	cgi_cookie_set (this->cgi, name, value,
					FCGX_GetParam("SCRIPT_NAME", this->req.envp),
					NULL, NULL, 0, 0);
}

/**
 * Implementation of request_t.redirect.
 */
static void redirect(private_request_t *this, char *fmt, ...)
{
	va_list args;

	FCGX_FPrintF(this->req.out, "Status: 303 See Other\n");
	FCGX_FPrintF(this->req.out, "Location: %s%s",
				 FCGX_GetParam("SCRIPT_NAME", this->req.envp),
				 *fmt == '/' ? "" : "/");
	va_start(args, fmt);
	FCGX_VFPrintF(this->req.out, fmt, args);
	va_end(args);
	FCGX_FPrintF(this->req.out, "\n\n");
}

/**
 * Implementation of request_t.to_referer.
 */
static void to_referer(private_request_t *this)
{
	FCGX_FPrintF(this->req.out, "Status: 303 See Other\n");
	FCGX_FPrintF(this->req.out, "Location: %s\n\n",
				 FCGX_GetParam("HTTP_REFERER", this->req.envp));
}

/**
 * Implementation of request_t.get_base.
 */
static char* get_base(private_request_t *this)
{
	return FCGX_GetParam("SCRIPT_NAME", this->req.envp);
}

/**
 * Implementation of request_t.session_closed.
 */
static bool session_closed(private_request_t *this)
{
	return this->closed;
}

/**
 * Implementation of request_t.close_session.
 */
static void close_session(private_request_t *this)
{
	this->closed = TRUE;
}

/**
 * Implementation of request_t.serve.
 */
static void serve(private_request_t *this, char *headers, chunk_t chunk)
{
	FCGX_FPrintF(this->req.out, "%s\n\n", headers);

	FCGX_PutStr(chunk.ptr, chunk.len, this->req.out);
}

/**
 * Implementation of request_t.render.
 */
static void render(private_request_t *this, char *template)
{
	NEOERR* err;

	thread_this->set(thread_this, this);
	err = cgi_display(this->cgi, template);
	if (err)
	{
		cgi_neo_error(this->cgi, err);
		nerr_log_error(err);
	}
	return;
}

/**
 * Implementation of request_t.streamf.
 */
static int streamf(private_request_t *this, char *format, ...)
{
	va_list args;
	int written;

	va_start(args, format);
	written = FCGX_VFPrintF(this->req.out, format, args);
	va_end(args);
	if (written >= 0 &&
		FCGX_FFlush(this->req.out) == -1)
	{
		return -1;
	}
	return written;
}

/**
 * Implementation of request_t.set.
 */
static void set(private_request_t *this, char *key, char *value)
{
	hdf_set_value(this->hdf, key, value);
}

/**
 * Implementation of request_t.setf.
 */
static void setf(private_request_t *this, char *format, ...)
{
	va_list args;

	va_start(args, format);
	hdf_set_valuevf(this->hdf, format, args);
	va_end(args);
}

/**
 * Implementation of request_t.get_ref.
 */
static request_t* get_ref(private_request_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

/**
 * Implementation of request_t.destroy
 */
static void destroy(private_request_t *this)
{
	if (ref_put(&this->ref))
	{
		thread_this->set(thread_this, this);
		cgi_destroy(&this->cgi);
		FCGX_Finish_r(&this->req);
		free(this);
	}
}

/**
 * This initialization method is guaranteed to run only once
 * for all threads.
 */
static void init(void)
{
	cgiwrap_init_emu(NULL, read_cb, writef_cb, write_cb,
					 getenv_cb, putenv_cb, iterenv_cb);
	thread_this = thread_value_create(NULL);
}

/*
 * see header file
 */
request_t *request_create(int fd, bool debug)
{
	NEOERR* err;
	private_request_t *this = malloc_thing(private_request_t);
	bool failed = FALSE;

	thread_cleanup_push(free, this);
	if (FCGX_InitRequest(&this->req, fd, 0) != 0 ||
		FCGX_Accept_r(&this->req) != 0)
	{
		failed = TRUE;
	}
	thread_cleanup_pop(failed);
	if (failed)
	{
		return NULL;
	}

	this->public.get_path = (char*(*)(request_t*))get_path;
	this->public.get_base = (char*(*)(request_t*))get_base;
	this->public.get_host = (char*(*)(request_t*))get_host;
	this->public.get_user_agent = (char*(*)(request_t*))get_user_agent;
	this->public.add_cookie = (void(*)(request_t*, char *name, char *value))add_cookie;
	this->public.get_cookie = (char*(*)(request_t*,char*))get_cookie;
	this->public.get_query_data = (char*(*)(request_t*, char *name))get_query_data;
	this->public.session_closed = (bool(*)(request_t*))session_closed;
	this->public.close_session = (void(*)(request_t*))close_session;
	this->public.redirect = (void(*)(request_t*, char *fmt,...))redirect;
	this->public.to_referer = (void(*)(request_t*))to_referer;
	this->public.render = (void(*)(request_t*,char*))render;
	this->public.streamf = (int(*)(request_t*, char *format, ...))streamf;
	this->public.serve = (void(*)(request_t*,char*,chunk_t))serve;
	this->public.set = (void(*)(request_t*, char *, char*))set;
	this->public.setf = (void(*)(request_t*, char *format, ...))setf;
	this->public.get_ref = (request_t*(*)(request_t*))get_ref;
	this->public.destroy = (void(*)(request_t*))destroy;

	pthread_once(&once, init);
	thread_this->set(thread_this, this);

	this->ref = 1;
	this->closed = FALSE;
	this->req_env_len = 0;
	while (this->req.envp[this->req_env_len] != NULL)
	{
		this->req_env_len++;
	}

	err = hdf_init(&this->hdf);
	if (!err)
	{
		hdf_set_value(this->hdf, "base", get_base(this));
		hdf_set_value(this->hdf, "Config.NoCache", "true");
		if (!debug)
		{
			hdf_set_value(this->hdf, "Config.TimeFooter", "0");
			hdf_set_value(this->hdf, "Config.CompressionEnabled", "1");
			hdf_set_value(this->hdf, "Config.WhiteSpaceStrip", "2");
		}

		err = cgi_init(&this->cgi, this->hdf);
		if (!err)
		{
			err = cgi_parse(this->cgi);
			if (!err)
			{
				return &this->public;
			}
			cgi_destroy(&this->cgi);
		}
	}
	nerr_log_error(err);
	FCGX_Finish_r(&this->req);
	free(this);
	return NULL;
}

