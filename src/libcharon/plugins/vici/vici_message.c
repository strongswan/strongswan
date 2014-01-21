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
 * Verify the occurence of a given type for given section/list nesting
 */
static bool verify_type(vici_type_t type, int section, bool list)
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
	if (!verify_type(type, this->section, this->list))
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
 * Write from enumerator to writer
 */
static bool write_from_enumerator(bio_writer_t *writer,
								  enumerator_t *enumerator)
{
	vici_type_t type;
	char *name;
	chunk_t value;
	int section = 0;
	bool list = FALSE;

	while (enumerator->enumerate(enumerator, &type, &name, &value))
	{
		if (!verify_type(type, section, list))
		{
			return FALSE;
		}

		if (type != VICI_END)
		{
			writer->write_uint8(writer, type);
		}

		switch (type)
		{
			case VICI_SECTION_START:
				writer->write_data8(writer, chunk_from_str(name));
				section++;
				break;
			case VICI_SECTION_END:
				section--;
				break;
			case VICI_KEY_VALUE:
				writer->write_data8(writer, chunk_from_str(name));
				writer->write_data16(writer, value);
				break;
			case VICI_LIST_START:
				writer->write_data8(writer, chunk_from_str(name));
				list = TRUE;
				break;
			case VICI_LIST_ITEM:
				writer->write_data16(writer, value);
				break;
			case VICI_LIST_END:
				list = FALSE;
				break;
			case VICI_END:
				return TRUE;
			default:
				return FALSE;
		}
	}
	return FALSE;
}

/**
 * See header
 */
vici_message_t *vici_message_create_from_enumerator(enumerator_t *enumerator)
{
	vici_message_t *message = NULL;
	bio_writer_t *writer;
	chunk_t data;

	writer = bio_writer_create(0);
	if (write_from_enumerator(writer, enumerator))
	{
		data = chunk_clone(writer->get_buf(writer));
		message = vici_message_create_from_data(data, TRUE);
	}
	enumerator->destroy(enumerator);
	writer->destroy(writer);

	return message;
}

/**
 * Enumerator for va_list arguments
 */
typedef struct {
	/* implements enumerator */
	enumerator_t public;
	/** arguments to enumerate */
	va_list args;
	/** first type, if not yet processed */
	vici_type_t *first;
} va_enumerator_t;

METHOD(enumerator_t, va_enumerate, bool,
	va_enumerator_t *this, vici_type_t *out, char **name, chunk_t *value)
{
	vici_type_t type;

	if (this->first)
	{
		type = *this->first;
		this->first = NULL;
	}
	else
	{
		type = va_arg(this->args, vici_type_t);
	}
	switch (type)
	{
		case VICI_SECTION_END:
		case VICI_LIST_END:
		case VICI_END:
			break;
		case VICI_LIST_START:
		case VICI_SECTION_START:
			*name = va_arg(this->args, char*);
			break;
		case VICI_KEY_VALUE:
			*name = va_arg(this->args, char*);
			*value = va_arg(this->args, chunk_t);
			break;
		case VICI_LIST_ITEM:
			*value = va_arg(this->args, chunk_t);
			break;
		default:
			return FALSE;
	}
	*out = type;
	return TRUE;
}

METHOD(enumerator_t, va_destroy, void,
	va_enumerator_t *this)
{
	va_end(this->args);
	free(this);
}

/**
 * See header
 */
vici_message_t *vici_message_create_from_args(vici_type_t type, ...)
{
	va_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = (void*)_va_enumerate,
			.destroy = _va_destroy,
		},
		.first = &type,
	);
	va_start(enumerator->args, type);

	return vici_message_create_from_enumerator(&enumerator->public);
}
