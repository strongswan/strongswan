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

#include <stdlib.h>

#include <utils/linked_list.h>

typedef struct {
	char *name;
	char *value;
} name_value_t;

/**
 * destroy a name value pair
 */
static void name_value_destroy(name_value_t *this)
{
	free(this->name);
	free(this->value);
	free(this);
}

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
	 * the associated fcgi request
	 */
	FCGX_Request *req;
	
	/**
	 * list of cookies (name_value_t)
	 */
	linked_list_t *cookies;
	
	/**
	 * list of post data (name_value_t)
	 */
	linked_list_t *posts;
};
	
/**
 * Implementation of request_t.get_cookie.
 */
static char* get_cookie(private_request_t *this, char *name)
{
	char *value = NULL;
	name_value_t *cookie;
	iterator_t *iterator;
	
	iterator = this->cookies->create_iterator(this->cookies, TRUE);
	while (iterator->iterate(iterator, (void**)&cookie))
	{
		if (streq(cookie->name, name))
		{
			value = cookie->value;
			break;
		}
	}
	iterator->destroy(iterator);
	return value;
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
static char* get_post_data(private_request_t *this, char *name)
{
	char *value = NULL;
	name_value_t *data;
	iterator_t *iterator;
	
	iterator = this->posts->create_iterator(this->posts, TRUE);
	while (iterator->iterate(iterator, (void**)&data))
	{
		if (streq(data->name, name))
		{
			value = data->value;
			break;
		}
	}
	iterator->destroy(iterator);
	return value;
}

/**
 * convert 2 digit hex string to a integer
 */
static char hex2char(char *hex)
{
	static char hexdig[] = "00112233445566778899AaBbCcDdEeFf";
	
	return (strchr(hexdig, hex[1]) - hexdig)/2 +
		   ((strchr(hexdig, hex[0]) - hexdig)/2 * 16);
}

/**
 * unescape a string up to the delimiter, and return a clone
 */
static char *unescape(char **pos, char delimiter)
{
	char *ptr, *res, *end, code[3] = {'\0','\0','\0'};

	if (**pos == '\0')
	{
		return NULL;
	}
	ptr = strchr(*pos, delimiter);
	if (ptr)
	{
		res = strndup(*pos, ptr - *pos);
		*pos = ptr + 1;
	}
	else
	{
		res = strdup(*pos);
		*pos = "";
	}
	end = res + strlen(res) + 1;
	/* replace '+' with ' ' */
	ptr = res;
	while ((ptr = strchr(ptr, '+')))
	{
		*ptr = ' ';
	}
	/* replace %HH with its ascii value */
	ptr = res;
	while ((ptr = strchr(ptr, '%')))
	{
		if (ptr > end - 2)
		{
			break;
		}
		strncpy(code, ptr + 1, 2);
		*ptr = hex2char(code);
		memmove(ptr + 1, ptr + 3, end - (ptr + 3));
	}
	return res;
}

/**
 * parse the http POST data
 */
static void parse_post(private_request_t *this)
{
	char buf[4096], *pos, *name, *value;
	name_value_t *data;
	int len;

	if (!streq(FCGX_GetParam("REQUEST_METHOD", this->req->envp), "POST") ||
		!streq(FCGX_GetParam("CONTENT_TYPE", this->req->envp),
			   "application/x-www-form-urlencoded"))
	{
		return;
	}
	
	len = FCGX_GetStr(buf, sizeof(buf) - 1, this->req->in);
	if (len != atoi(FCGX_GetParam("CONTENT_LENGTH", this->req->envp)))
	{
		return;
	}
	buf[len] = 0;
	
	pos = buf;
	while (TRUE)
	{
		name = unescape(&pos, '=');
		if (name)
		{
			value = unescape(&pos, '&');
			if (value)
			{
				data = malloc_thing(name_value_t);
				data->name = name;
				data->value = value;
				this->posts->insert_last(this->posts, data);
				continue;
			}
			else
			{
				free(name);
			}
		}
		break;
	}
}

/**
 * parse the requests cookies
 */
static void parse_cookies(private_request_t *this)
{
	char *str, *pos;
	name_value_t *cookie;
	
	str = FCGX_GetParam("HTTP_COOKIE", this->req->envp);
	while (str)
	{
		if (*str == ' ')
		{
			str++;
			continue;
		}
		pos = strchr(str, '=');
		if (pos == NULL)
		{
			break;
		}
		cookie = malloc_thing(name_value_t);
		cookie->name = strndup(str, pos - str);
		cookie->value = NULL;
		str = pos + 1;
		if (str)
		{
			pos = strchr(str, ';');
			if (pos)
			{
				cookie->value = strndup(str, pos - str);
			}
			else
			{
				cookie->value = strdup(str);
			}
		}
		this->cookies->insert_last(this->cookies, cookie);
		if (pos == NULL)
		{
			break;
		}
		str = pos + 1;
	}
}

/**
 * Implementation of request_t.destroy
 */
static void destroy(private_request_t *this)
{
	this->cookies->destroy_function(this->cookies, (void*)name_value_destroy);
	this->posts->destroy_function(this->posts, (void*)name_value_destroy);
	free(this);
}

/*
 * see header file
 */
request_t *request_create(FCGX_Request *request)
{
	private_request_t *this = malloc_thing(private_request_t);

	this->public.get_path = (char*(*)(request_t*))get_path;
	this->public.get_cookie = (char*(*)(request_t*,char*))get_cookie;
	this->public.get_post_data = (char*(*)(request_t*, char *name))get_post_data;
	this->public.destroy = (void(*)(request_t*))destroy;
	
	this->req = request;
	this->cookies = linked_list_create();
	this->posts = linked_list_create();
	
	parse_cookies(this);
	parse_post(this);
	
	return &this->public;
}

