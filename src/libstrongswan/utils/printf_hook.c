/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2006-2008 Martin Willi
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

#include "printf_hook.h"

#include "utils.h"
#include "debug.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

typedef struct private_printf_hook_t private_printf_hook_t;
typedef struct printf_hook_handler_t printf_hook_handler_t;

#define PRINTF_BUF_LEN 8192
#define ARGS_MAX 3

/**
 * private data of printf_hook
 */
struct private_printf_hook_t {

	/**
	 * public functions
	 */
	printf_hook_t public;
};

/**
 * struct with information about a registered handler
 */
struct printf_hook_handler_t {

	/**
	 * callback function
	 */
	printf_hook_function_t hook;

	/**
	 * number of arguments
	 */
	int numargs;

	/**
	 * types of the arguments
	 */
	int argtypes[ARGS_MAX];

#ifdef USE_VSTR
	/**
	 * name required for Vstr
	 */
	char *name;
#endif
};

/* A-Z | 6 other chars | a-z */
#define NUM_HANDLERS 58
static printf_hook_handler_t *printf_hooks[NUM_HANDLERS];

#define SPEC_TO_INDEX(spec) ((int)(spec) - (int)'A')
#define IS_VALID_SPEC(spec) (SPEC_TO_INDEX(spec) > -1 && SPEC_TO_INDEX(spec) < NUM_HANDLERS)

#if !defined(USE_VSTR) && \
	(defined(HAVE_PRINTF_FUNCTION) || defined(HAVE_PRINTF_SPECIFIER))

/**
 * Printf hook print function. This is actually of type "printf_function",
 * however glibc does it typedef to function, but uclibc to a pointer.
 * So we redefine it here.
 */
static int custom_print(FILE *stream, const struct printf_info *info,
						const void *const *args)
{
	printf_hook_spec_t spec;
	printf_hook_handler_t *handler = printf_hooks[SPEC_TO_INDEX(info->spec)];
	printf_hook_data_t data = {
		.stream = stream,
	};

	spec.hash = info->alt;
	spec.plus = info->showsign;
	spec.minus = info->left;
	spec.width = info->width;

	return handler->hook(&data, &spec, args);
}

/**
 * Printf hook arginfo function, which is actually of type
 * "printf_arginfo_[size_]function".
 */
static int custom_arginfo(const struct printf_info *info, size_t n, int *argtypes
#ifdef HAVE_PRINTF_SPECIFIER
						  , int *size
#endif
						  )
{
	int i;
	printf_hook_handler_t *handler = printf_hooks[SPEC_TO_INDEX(info->spec)];

	if (handler->numargs <= n)
	{
		for (i = 0; i < handler->numargs; ++i)
		{
			argtypes[i] = handler->argtypes[i];
		}
	}
	/* we never set "size", as we have no user defined types */
	return handler->numargs;
}

#else

#include <errno.h>
#include <unistd.h> /* for STDOUT_FILENO */

/**
 * These are used below, whenever the public wrapper functions are called before
 * initialization or after destruction.
 */
#undef vprintf
#undef vfprintf
#undef vsnprintf

/**
 * Vstr custom format specifier callback function.
 */
static int custom_fmt_cb(Vstr_base *base, size_t pos, Vstr_fmt_spec *fmt_spec)
{
	int i;
	const void *args[ARGS_MAX];
	printf_hook_spec_t spec;
	printf_hook_handler_t *handler = printf_hooks[SPEC_TO_INDEX(fmt_spec->name[0])];
	printf_hook_data_t data = {
		.base = base,
		.pos = pos,
	};

	for (i = 0; i < handler->numargs; i++)
	{
		switch(handler->argtypes[i])
		{
			case PRINTF_HOOK_ARGTYPE_INT:
				args[i] = VSTR_FMT_CB_ARG_PTR(fmt_spec, i);
				break;
			case PRINTF_HOOK_ARGTYPE_POINTER:
				args[i] = &VSTR_FMT_CB_ARG_PTR(fmt_spec, i);
				break;
		}
	}

	spec.hash = fmt_spec->fmt_hash;
	spec.plus = fmt_spec->fmt_plus;
	spec.minus = fmt_spec->fmt_minus;
	spec.width = fmt_spec->fmt_field_width;

	handler->hook(&data, &spec, args);
	return 1;
}

/**
 * Add a custom format handler to the given Vstr_conf object
 */
static void vstr_fmt_add_handler(Vstr_conf *conf, printf_hook_handler_t *handler)
{
	int *at = handler->argtypes;
	switch(handler->numargs)
	{
		case 1:
			vstr_fmt_add(conf, handler->name, custom_fmt_cb, at[0],
						 VSTR_TYPE_FMT_END);
			break;
		case 2:
			vstr_fmt_add(conf, handler->name, custom_fmt_cb, at[0],
						 at[1], VSTR_TYPE_FMT_END);
			break;
		case 3:
			vstr_fmt_add(conf, handler->name, custom_fmt_cb, at[0],
						 at[1], at[2], VSTR_TYPE_FMT_END);
			break;
	}
}

/**
 * Management of thread-specific Vstr_conf objects
 */
#include <threading/thread_value.h>

static thread_value_t *vstr_conf = NULL;

static Vstr_conf *create_vstr_conf()
{
	int i;
	Vstr_conf *conf = vstr_make_conf();
	vstr_cntl_conf(conf, VSTR_CNTL_CONF_SET_FMT_CHAR_ESC, '%');
	vstr_cntl_conf(conf, VSTR_CNTL_CONF_SET_TYPE_GRPALLOC_CACHE,
						 VSTR_TYPE_CNTL_CONF_GRPALLOC_CSTR);
	vstr_cntl_conf(conf, VSTR_CNTL_CONF_SET_NUM_BUF_SZ, PRINTF_BUF_LEN);
	for (i = 0; i < NUM_HANDLERS; ++i)
	{
		printf_hook_handler_t *handler = printf_hooks[i];
		if (handler)
		{
			vstr_fmt_add_handler(conf, handler);
		}
	}
	return conf;
}

static inline Vstr_conf *get_vstr_conf()
{
	Vstr_conf *conf = NULL;
	if (vstr_conf)
	{
		conf = (Vstr_conf*)vstr_conf->get(vstr_conf);
		if (!conf)
		{
			conf = create_vstr_conf();
			vstr_conf->set(vstr_conf, conf);
		}
	}
	return conf;
}

/**
 * Described in header
 */
size_t vstr_print_in_hook(struct Vstr_base *base, size_t pos, const char *fmt,
						  ...)
{
	va_list args;
	int written;

	va_start(args, fmt);
	written = vstr_add_vfmt(base, pos, fmt, args);
	va_end(args);
	return written;
}

/**
 * Wrapper functions for printf and alike
 */
int vstr_wrapper_printf(const char *format, ...)
{
	int written;
	va_list args;
	va_start(args, format);
	written = vstr_wrapper_vprintf(format, args);
	va_end(args);
	return written;
}
int vstr_wrapper_fprintf(FILE *stream, const char *format, ...)
{
	int written;
	va_list args;
	va_start(args, format);
	written = vstr_wrapper_vfprintf(stream, format, args);
	va_end(args);
	return written;
}
int vstr_wrapper_sprintf(char *str, const char *format, ...)
{
	int written;
	va_list args;
	va_start(args, format);
	written = vstr_wrapper_vsprintf(str, format, args);
	va_end(args);
	return written;
}
int vstr_wrapper_snprintf(char *str, size_t size, const char *format, ...)
{
	int written;
	va_list args;
	va_start(args, format);
	written = vstr_wrapper_vsnprintf(str, size, format, args);
	va_end(args);
	return written;
}
int vstr_wrapper_asprintf(char **str, const char *format, ...)
{
	int written;
	va_list args;
	va_start(args, format);
	written = vstr_wrapper_vasprintf(str, format, args);
	va_end(args);
	return written;
}
static inline int vstr_wrapper_vprintf_internal(Vstr_conf *conf, int fd,
												const char *format,
												va_list args)
{
	int written;
	Vstr_base *s = vstr_make_base(conf);
	vstr_add_vfmt(s, 0, format, args);
	written = s->len;
	while (s->len)
	{
		if (!vstr_sc_write_fd(s, 1, s->len, fd, NULL))
		{
			if (errno != EAGAIN && errno != EINTR)
			{
				written -= s->len;
				break;
			}
		}
	}
	vstr_free_base(s);
	return written;
}
int vstr_wrapper_vprintf(const char *format, va_list args)
{
	Vstr_conf *conf = get_vstr_conf();
	if (conf)
	{
		return vstr_wrapper_vprintf_internal(conf, STDOUT_FILENO, format, args);
	}
	return vprintf(format, args);
}
int vstr_wrapper_vfprintf(FILE *stream, const char *format, va_list args)
{
	Vstr_conf *conf = get_vstr_conf();
	if (conf)
	{
		return vstr_wrapper_vprintf_internal(conf, fileno(stream), format,
											 args);
	}
	return vfprintf(stream, format, args);
}
static inline int vstr_wrapper_vsnprintf_internal(char *str, size_t size,
												  const char *format,
												  va_list args)
{
	Vstr_conf *conf = get_vstr_conf();
	if (conf)
	{
		int written;
		Vstr_base *s = vstr_make_base(conf);
		vstr_add_vfmt(s, 0, format, args);
		written = s->len;
		vstr_export_cstr_buf(s, 1, s->len, str, (size > 0) ? size : s->len + 1);
		vstr_free_base(s);
		return written;
	}
	return vsnprintf(str, size, format, args);
}
int vstr_wrapper_vsprintf(char *str, const char *format, va_list args)
{
	return vstr_wrapper_vsnprintf_internal(str, 0, format, args);
}
int vstr_wrapper_vsnprintf(char *str, size_t size, const char *format,
						   va_list args)
{
	return (size > 0) ? vstr_wrapper_vsnprintf_internal(str, size, format, args) : 0;
}
int vstr_wrapper_vasprintf(char **str, const char *format, va_list args)
{
	size_t len = 100;
	int written;
	*str = malloc(len);
	while (TRUE)
	{
		va_list ac;
		va_copy(ac, args);
		written = vstr_wrapper_vsnprintf_internal(*str, len, format, ac);
		va_end(ac);
		if (written < len)
		{
			break;
		}
		len = written + 1;
		*str = realloc(*str, len);
	}
	return written;
}
#endif

METHOD(printf_hook_t, add_handler, void,
	private_printf_hook_t *this, char spec,
						printf_hook_function_t hook, ...)
{
	int i = -1;
	printf_hook_handler_t *handler;
	printf_hook_argtype_t argtype;
	va_list args;

	if (!IS_VALID_SPEC(spec))
	{
		DBG1(DBG_LIB, "'%c' is not a valid printf hook specifier, "
			 "not registered!", spec);
		return;
	}

	handler = malloc_thing(printf_hook_handler_t);
	handler->hook = hook;

	va_start(args, hook);
	while ((argtype = va_arg(args, printf_hook_argtype_t)) != PRINTF_HOOK_ARGTYPE_END)
	{
		if (++i >= ARGS_MAX)
		{
			DBG1(DBG_LIB, "Too many arguments for printf hook with "
				 "specifier '%c', not registered!", spec);
			va_end(args);
			free(handler);
			return;
		}
		handler->argtypes[i] = argtype;
	}
	va_end(args);

	handler->numargs = i + 1;

	if (handler->numargs > 0)
	{
#if !defined(USE_VSTR) && \
	(defined(HAVE_PRINTF_FUNCTION) || defined(HAVE_PRINTF_SPECIFIER))
#	ifdef HAVE_PRINTF_SPECIFIER
		register_printf_specifier(spec, custom_print, custom_arginfo);
#	else
		register_printf_function(spec, custom_print, custom_arginfo);
#	endif
#else
		Vstr_conf *conf = get_vstr_conf();
		handler->name = malloc(2);
		handler->name[0] = spec;
		handler->name[1] = '\0';
		vstr_fmt_add_handler(conf, handler);
#endif
		printf_hooks[SPEC_TO_INDEX(spec)] = handler;
	}
	else
	{
		free(handler);
	}
}

METHOD(printf_hook_t, destroy, void,
	private_printf_hook_t *this)
{
	int i;
#ifdef USE_VSTR
	Vstr_conf *conf = get_vstr_conf();
#endif

	for (i = 0; i < NUM_HANDLERS; ++i)
	{
		printf_hook_handler_t *handler = printf_hooks[i];
		if (handler)
		{
#ifdef USE_VSTR
			vstr_fmt_del(conf, handler->name);
			free(handler->name);
#endif
			free(handler);
		}
	}

#ifdef USE_VSTR
	/* freeing the Vstr_conf of the main thread */
	vstr_conf->destroy(vstr_conf);
	vstr_conf = NULL;
	vstr_exit();
#endif
	free(this);
}

/*
 * see header file
 */
printf_hook_t *printf_hook_create()
{
	private_printf_hook_t *this;

	INIT(this,
		.public = {
			.add_handler = _add_handler,
			.destroy = _destroy,
		},
	);

	memset(printf_hooks, 0, sizeof(printf_hooks));

#ifdef USE_VSTR
	if (!vstr_init())
	{
		DBG1(DBG_LIB, "failed to initialize Vstr library!");
		free(this);
		return NULL;
	}
	vstr_conf = thread_value_create((thread_cleanup_t)vstr_free_conf);
#endif

	return &this->public;
}

