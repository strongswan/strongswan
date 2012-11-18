/*
 * Copyright (C) 2011-2012 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "ita_attr.h"
#include "ita_attr_command.h"

#include <pen/pen.h>
#include <utils/debug.h>

#include <string.h>

typedef struct private_ita_attr_command_t private_ita_attr_command_t;

/**
 * Private data of an ita_attr_command_t object.
 */
struct private_ita_attr_command_t {

	/**
	 * Public members of ita_attr_command_t
	 */
	ita_attr_command_t public;

	/**
	 * Vendor-specific attribute type
	 */
	pen_type_t type;

	/**
	 * Attribute value
	 */
	chunk_t value;

	/**
	 * Noskip flag
	 */
	bool noskip_flag;

	/**
	 * Command string
	 */
	char *command;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(pa_tnc_attr_t, get_type, pen_type_t,
	private_ita_attr_command_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_ita_attr_command_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_ita_attr_command_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_ita_attr_command_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_ita_attr_command_t *this)
{
	if (this->value.ptr)
	{
		return;
	}
	this->value = chunk_create(this->command, strlen(this->command));
	this->value = chunk_clone(this->value);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_ita_attr_command_t *this, u_int32_t *offset)
{
	this->command = strndup(this->value.ptr, this->value.len);

	return SUCCESS;
}

METHOD(pa_tnc_attr_t, get_ref, pa_tnc_attr_t*,
	private_ita_attr_command_t *this)
{
	ref_get(&this->ref);
	return &this->public.pa_tnc_attribute;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_ita_attr_command_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this->value.ptr);
		free(this->command);
		free(this);
	}
}

METHOD(ita_attr_command_t, get_command, char*,
	private_ita_attr_command_t *this)
{
	return this->command;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ita_attr_command_create(char *command)
{
	private_ita_attr_command_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_command = _get_command,
		},
		.type = { PEN_ITA, ITA_ATTR_COMMAND },
		.command = strdup(command),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ita_attr_command_create_from_data(chunk_t data)
{
	private_ita_attr_command_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
			.get_command = _get_command,
		},
		.type = {PEN_ITA, ITA_ATTR_COMMAND },
		.value = chunk_clone(data),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}


