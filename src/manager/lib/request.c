/**
 * @file request.c
 *
 * @brief Implementation of request_t.
 *
 */

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
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ClearSilver/ClearSilver.h>

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
	FCGX_Request *req;
	
	/**
	 * ClearSilver CGI Kit context
	 */
	CGI *cgi;
	
	/**
	 * ClearSilver HDF dataset for this request
	 */
	HDF *hdf;
};

/**
 * key to a thread specific FCGX_Request, used for ClearSilver cgiwrap callbacks.
 * ClearSilver cgiwrap is not threadsave, so we use a private
 * context for each thread.
 */
static pthread_key_t req_key;

/**
 * length of param list in req->envp
 */
static pthread_key_t req_env_len_key;

/**
 * control variable for pthread_once
 */
pthread_once_t once = PTHREAD_ONCE_INIT;

/**
 * fcgiwrap read callback
 */
static int read_cb(void *null, char *buf, int size)
{
	FCGX_Request *req = (FCGX_Request*)pthread_getspecific(req_key);
	return FCGX_GetStr(buf, size, req->in);
}

/**
 * fcgiwrap writef callback
 */
static int writef_cb(void *null, const char *format, va_list args)
{
	FCGX_Request *req = (FCGX_Request*)pthread_getspecific(req_key);
	FCGX_VFPrintF(req->out, format, args);
	return 0;
}
/**
 * fcgiwrap write callback
 */
static int write_cb(void *null, const char *buf, int size)
{
	FCGX_Request *req = (FCGX_Request*)pthread_getspecific(req_key);
	return FCGX_PutStr(buf, size, req->out);
}

/**
 * fcgiwrap getenv callback
 */
static char *getenv_cb(void *null, const char *key)
{
	char *value;
	FCGX_Request *req = (FCGX_Request*)pthread_getspecific(req_key);
	value = FCGX_GetParam(key, req->envp);
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
	FCGX_Request *req = (FCGX_Request*)pthread_getspecific(req_key);
	int req_env_len = (int)pthread_getspecific(req_env_len_key);
	if (num < req_env_len)
	{
		char *eq;

		eq = strchr(req->envp[num], '=');
		if (eq)
		{
			*key = strndup(req->envp[num], eq - req->envp[num]);
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
	char * path = FCGX_GetParam("PATH_INFO", this->req->envp);
	return path ? path : "";
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
	cgi_cookie_set (this->cgi, name, value,
					FCGX_GetParam("SCRIPT_NAME", this->req->envp),
					NULL, NULL, 0, 0);
}
	
/**
 * Implementation of request_t.redirect.
 */
static void redirect(private_request_t *this, char *fmt, ...)
{
	va_list args;

	FCGX_FPrintF(this->req->out, "Status: 303 See Other\n");
	FCGX_FPrintF(this->req->out, "Location: %s%s",
				 FCGX_GetParam("SCRIPT_NAME", this->req->envp),
				 *fmt == '/' ? "" : "/");
	va_start(args, fmt);
	FCGX_VFPrintF(this->req->out, fmt, args);
	va_end(args);
	FCGX_FPrintF(this->req->out, "\n\n");
}

/**
 * Implementation of request_t.get_base.
 */
static char* get_base(private_request_t *this)
{
	return FCGX_GetParam("SCRIPT_NAME", this->req->envp);
}

/**
 * Implementation of request_t.serve.
 */
static void serve(private_request_t *this, char *headers, chunk_t chunk)
{
	FCGX_FPrintF(this->req->out, "%s\n\n", headers);

	FCGX_PutStr(chunk.ptr, chunk.len, this->req->out);
}

/**
 * Implementation of request_t.render.
 */
static void render(private_request_t *this, char *template)
{
	NEOERR* err;
	
	err = cgi_display(this->cgi, template);
	if (err)
	{
		cgi_neo_error(this->cgi, err);
		nerr_log_error(err);
	}
	return;
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
 * Implementation of request_t.destroy
 */
static void destroy(private_request_t *this)
{
	cgi_destroy(&this->cgi);
	free(this);
}

/**
 * This initialization method is guaranteed to run only once
 * for all threads.
 */
static void init(void)
{
	cgiwrap_init_emu(NULL, read_cb, writef_cb, write_cb,
	                 getenv_cb, putenv_cb, iterenv_cb);
	pthread_key_create(&req_key, NULL);
	pthread_key_create(&req_env_len_key, NULL);
}

/*
 * see header file
 */
request_t *request_create(FCGX_Request *request, bool debug)
{
	NEOERR* err;
	private_request_t *this = malloc_thing(private_request_t);

	this->public.get_path = (char*(*)(request_t*))get_path;
	this->public.get_base = (char*(*)(request_t*))get_base;
	this->public.add_cookie = (void(*)(request_t*, char *name, char *value))add_cookie;
	this->public.get_cookie = (char*(*)(request_t*,char*))get_cookie;
	this->public.get_query_data = (char*(*)(request_t*, char *name))get_query_data;
	this->public.redirect = (void(*)(request_t*, char *fmt,...))redirect;
	this->public.render = (void(*)(request_t*,char*))render;
	this->public.serve = (void(*)(request_t*,char*,chunk_t))serve;
	this->public.set = (void(*)(request_t*, char *, char*))set;
	this->public.setf = (void(*)(request_t*, char *format, ...))setf;
	this->public.destroy = (void(*)(request_t*))destroy;
	
	pthread_once(&once, init);
	
	this->req = request;
	pthread_setspecific(req_key, (void*)request);
	
	int req_env_len = 0;
	while (request->envp[req_env_len] != NULL)
	{
		req_env_len++;
	}
	
	pthread_setspecific(req_env_len_key, (void*)req_env_len);
	
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
	free(this);
	return NULL;
}

