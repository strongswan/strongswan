/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "vici_message.h"
#include "vici_builder.h"

#include <bio/bio_reader.h>
#include <bio/bio_writer.h>

typedef struct private_vici_message_t private_vici_message_t;

/**
 * Private data of an vici_message_t object.
 */
struct private_vici_message_t {

	/**
	 * Public vici_message_t interface.
	 */
	vici_message_t public;

	/**
	 * Message encoding
	 */
	chunk_t encoding;

	/**
	 * Free encoding during destruction?
	 */
	bool cleanup;
};

ENUM(vici_type_names, VICI_SECTION_START, VICI_END,
	"section-start",
	"section-end",
	"key-value",
	"list-start",
	"list-item",
	"list-end",
	"end"
);

/**
 * See header.
 */
bool vici_stringify(chunk_t chunk, char *buf, size_t size)
{
	if (!chunk_printable(chunk, NULL, 0))
	{
		return FALSE;
	}
	snprintf(buf, size, "%.*s", (int)chunk.len, chunk.ptr);
	return TRUE;
}

/**
 * See header.
 */
bool vici_verify_type(vici_type_t type, u_int section, bool list)
{
	if (list)
	{
		if (type != VICI_LIST_END && type != VICI_LIST_ITEM)
		{
			DBG1(DBG_ENC, "'%N' within list", vici_type_names, type);
			return FALSE;
		}
	}
	else
	{
		if (type == VICI_LIST_ITEM || type == VICI_LIST_END)
		{
			DBG1(DBG_ENC, "'%N' outside list", vici_type_names, type);
			return FALSE;
		}
	}
	if (type == VICI_SECTION_END && section == 0)
	{
		DBG1(DBG_ENC, "'%N' outside of section", vici_type_names, type);
		return FALSE;
	}
	if (type == VICI_END)
	{
		if (section)
		{
			DBG1(DBG_ENC, "'%N' within section", vici_type_names, type);
			return FALSE;
		}
		if (list)
		{
			DBG1(DBG_ENC, "'%N' within list", vici_type_names, type);
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Enumerator parsing message
 */
typedef struct {
	/* implements enumerator */
	enumerator_t public;
	/** reader to parse from */
	bio_reader_t *reader;
	/** section nesting level */
	int section;
	/** currently parsing list? */
	bool list;
	/** string currently enumerating */
	char name[257];
} parse_enumerator_t;

METHOD(enumerator_t, parse_enumerate, bool,
	parse_enumerator_t *this, vici_type_t *out, char **name, chunk_t *value)
{
	u_int8_t type;
	chunk_t data;

	if (!this->reader->read_uint8(this->reader, &type))
	{
		*out = VICI_END;
		return TRUE;
	}
	if (!vici_verify_type(type, this->section, this->list))
	{
		return FALSE;
	}

	switch (type)
	{
		case VICI_SECTION_START:
			if (!this->reader->read_data8(this->reader, &data) ||
				!vici_stringify(data, this->name, sizeof(this->name)))
			{
				DBG1(DBG_ENC, "invalid '%N' encoding", vici_type_names, type);
				return FALSE;
			}
			*name = this->name;
			this->section++;
			break;
		case VICI_SECTION_END:
			this->section--;
			break;
		case VICI_KEY_VALUE:
			if (!this->reader->read_data8(this->reader, &data) ||
				!vici_stringify(data, this->name, sizeof(this->name)) ||
				!this->reader->read_data16(this->reader, value))
			{
				DBG1(DBG_ENC, "invalid '%N' encoding", vici_type_names, type);
				return FALSE;
			}
			*name = this->name;
			break;
		case VICI_LIST_START:
			if (!this->reader->read_data8(this->reader, &data) ||
				!vici_stringify(data, this->name, sizeof(this->name)))
			{
				DBG1(DBG_ENC, "invalid '%N' encoding", vici_type_names, type);
				return FALSE;
			}
			*name = this->name;
			this->list = TRUE;
			break;
		case VICI_LIST_ITEM:
			this->reader->read_data16(this->reader, value);
			break;
		case VICI_LIST_END:
			this->list = FALSE;
			break;
		case VICI_END:
			return TRUE;
		default:
			DBG1(DBG_ENC, "unknown encoding type: %u", type);
			return FALSE;
	}

	*out = type;

	return TRUE;
}

METHOD(enumerator_t, parse_destroy, void,
	parse_enumerator_t *this)
{
	this->reader->destroy(this->reader);
	free(this);
}

METHOD(vici_message_t, create_enumerator, enumerator_t*,
	private_vici_message_t *this)
{
	parse_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = (void*)_parse_enumerate,
			.destroy = _parse_destroy,
		},
		.reader = bio_reader_create(this->encoding),
	);

	return &enumerator->public;
}

METHOD(vici_message_t, get_encoding, chunk_t,
	private_vici_message_t *this)
{
	return this->encoding;
}

METHOD(vici_message_t, destroy, void,
	private_vici_message_t *this)
{
	if (this->cleanup)
	{
		chunk_clear(&this->encoding);
	}
	free(this);
}

/**
 * See header
 */
vici_message_t *vici_message_create_from_data(chunk_t data, bool cleanup)
{
	private_vici_message_t *this;

	INIT(this,
		.public = {
			.create_enumerator = _create_enumerator,
			.get_encoding = _get_encoding,
			.destroy = _destroy,
		},
		.encoding = data,
		.cleanup = cleanup,
	);

	return &this->public;
}

/**
 * See header
 */
vici_message_t *vici_message_create_from_enumerator(enumerator_t *enumerator)
{
	vici_builder_t *builder;
	vici_type_t type;
	char *name;
	chunk_t value;

	builder = vici_builder_create();
	while (enumerator->enumerate(enumerator, &type, &name, &value))
	{
		switch (type)
		{
			case VICI_SECTION_START:
			case VICI_LIST_START:
				builder->add(builder, type, name);
				continue;
			case VICI_KEY_VALUE:
				builder->add(builder, type, name, value);
				continue;
			case VICI_LIST_ITEM:
				builder->add(builder, type, value);
				continue;
			case VICI_SECTION_END:
			case VICI_LIST_END:
			default:
				builder->add(builder, type);
				continue;
			case VICI_END:
				break;
		}
		break;
	}
	enumerator->destroy(enumerator);

	return builder->finalize(builder);
}

/**
 * See header
 */
vici_message_t *vici_message_create_from_args(vici_type_t type, ...)
{
	vici_builder_t *builder;
	va_list args;
	char *name;
	chunk_t value;

	builder = vici_builder_create();
	va_start(args, type);
	while (type != VICI_END)
	{
		switch (type)
		{
			case VICI_LIST_START:
			case VICI_SECTION_START:
				name = va_arg(args, char*);
				builder->add(builder, type, name);
				break;
			case VICI_KEY_VALUE:
				name = va_arg(args, char*);
				value = va_arg(args, chunk_t);
				builder->add(builder, type, name, value);
				break;
			case VICI_LIST_ITEM:
				value = va_arg(args, chunk_t);
				builder->add(builder, type, value);
				break;
			case VICI_SECTION_END:
			case VICI_LIST_END:
			default:
				builder->add(builder, type);
				break;
		}
		type = va_arg(args, vici_type_t);
	}
	va_end(args);
	return builder->finalize(builder);
}
