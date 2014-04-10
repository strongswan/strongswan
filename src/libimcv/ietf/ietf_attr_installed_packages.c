/*
 * Copyright (C) 2012-2014 Andreas Steffen
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

#include "ietf_attr_installed_packages.h"

#include <string.h>

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <collections/linked_list.h>
#include <utils/debug.h>


typedef struct private_ietf_attr_installed_packages_t private_ietf_attr_installed_packages_t;
typedef struct package_entry_t package_entry_t;

/**
 * PA-TNC Installed Packages Type  (see section 4.2.7 of RFC 5792)
 *
 *                       1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Reserved             |         Package Count         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Pkg Name Len  |        Package Name (Variable Length)         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Version Len  |    Package Version Number (Variable Length)   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * Private data of an ietf_attr_installed_packages_t object.
 */
struct private_ietf_attr_installed_packages_t {

	/**
	 * Public members of ietf_attr_installed_packages_t
	 */
	ietf_attr_installed_packages_t public;

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
	 * List of Installed Package entries
	 */
	linked_list_t *packages;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

/**
 * Package entry
 */
struct package_entry_t {
	chunk_t name;
	chunk_t version;
};

/**
 * Free a package entry
 */
static void free_package_entry(package_entry_t *entry)
{
	free(entry->name.ptr);
	free(entry->version.ptr);
	free(entry);
}

METHOD(pa_tnc_attr_t, get_type, pen_type_t,
	private_ietf_attr_installed_packages_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_ietf_attr_installed_packages_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_ietf_attr_installed_packages_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_ietf_attr_installed_packages_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_ietf_attr_installed_packages_t *this)
{
	bio_writer_t *writer;
	enumerator_t *enumerator;
	package_entry_t *entry;

	if (this->value.ptr)
	{
		return;
	}
	writer = bio_writer_create(IETF_INSTALLED_PACKAGES_MIN_SIZE);
	writer->write_uint16(writer, 0x0000);
	writer->write_uint16(writer, this->packages->get_count(this->packages));

	enumerator = this->packages->create_enumerator(this->packages);
	while (enumerator->enumerate(enumerator, &entry))
	{
		writer->write_data8(writer, entry->name);
		writer->write_data8(writer, entry->version);
	}
	enumerator->destroy(enumerator);

	this->value = writer->extract_buf(writer);
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_ietf_attr_installed_packages_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	package_entry_t *entry;
	status_t status = FAILED;
	chunk_t name, version;
	u_int16_t reserved, count;
	u_char *pos;

	*offset = 0;

	if (this->value.len < IETF_INSTALLED_PACKAGES_MIN_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for IETF installed packages");
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	reader->read_uint16(reader, &reserved);
	reader->read_uint16(reader, &count);
	*offset = IETF_INSTALLED_PACKAGES_MIN_SIZE;

	while (reader->remaining(reader))
	{
		if (!reader->read_data8(reader, &name))
		{
			DBG1(DBG_TNC, "insufficient data for IETF installed package name");
			goto end;
		}
		pos = memchr(name.ptr, '\0', name.len);
		if (pos)
		{
			DBG1(DBG_TNC, "nul termination in IETF installed package name");
			*offset += 1 + (pos - name.ptr);
			goto end;
		}
		*offset += 1 + name.len;

		if (!reader->read_data8(reader, &version))
		{
			DBG1(DBG_TNC, "insufficient data for IETF installed package version");
			goto end;
		}
		pos = memchr(version.ptr, '\0', version.len);
		if (pos)
		{
			DBG1(DBG_TNC, "nul termination in IETF installed package version");
			*offset += 1 + (pos - version.ptr);
			goto end;
		}
		*offset += 1 + version.len;

		entry = malloc_thing(package_entry_t);
		entry->name = chunk_clone(name);
		entry->version = chunk_clone(version);
		this->packages->insert_last(this->packages, entry);
	}

	if (count != this->packages->get_count(this->packages))
	{
		DBG1(DBG_TNC, "IETF installed package count unequal to "
					  "number of included packages");
		goto end;
	}
	status = SUCCESS;

end:
	reader->destroy(reader);
	return status;
}

METHOD(pa_tnc_attr_t, get_ref, pa_tnc_attr_t*,
	private_ietf_attr_installed_packages_t *this)
{
	ref_get(&this->ref);
	return &this->public.pa_tnc_attribute;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_ietf_attr_installed_packages_t *this)
{
	if (ref_put(&this->ref))
	{
		this->packages->destroy_function(this->packages, (void*)free_package_entry);
		free(this->value.ptr);
		free(this);
	}
}

METHOD(ietf_attr_installed_packages_t, add, void,
	private_ietf_attr_installed_packages_t *this, chunk_t name, chunk_t version)
{
	package_entry_t *entry;

	/* restrict package name and package version number fields to 255 octets */
	name.len = min(255, name.len);
	version.len = min(255, version.len);

	entry = malloc_thing(package_entry_t);
	entry->name = chunk_clone(name);
	entry->version = chunk_clone(version);
	this->packages->insert_last(this->packages, entry);
}

/**
 * Enumerate package filter entries
 */
static bool package_filter(void *null, package_entry_t **entry, chunk_t *name,
						   void *i2, chunk_t *version)
{
	*name = (*entry)->name;
	*version = (*entry)->version;
	return TRUE;
}

METHOD(ietf_attr_installed_packages_t, create_enumerator, enumerator_t*,
	private_ietf_attr_installed_packages_t *this)
{
	return enumerator_create_filter(
						this->packages->create_enumerator(this->packages),
						(void*)package_filter, NULL, NULL);
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_attr_installed_packages_create(void)
{
	private_ietf_attr_installed_packages_t *this;

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
			.add = _add,
			.create_enumerator = _create_enumerator,
		},
		.type = { PEN_IETF, IETF_ATTR_INSTALLED_PACKAGES },
		.packages = linked_list_create(),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *ietf_attr_installed_packages_create_from_data(chunk_t data)
{
	private_ietf_attr_installed_packages_t *this;

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
			.add = _add,
			.create_enumerator = _create_enumerator,
		},
		.type = {PEN_IETF, IETF_ATTR_INSTALLED_PACKAGES },
		.value = chunk_clone(data),
		.packages = linked_list_create(),
		.ref = 1,
	);

	return &this->public.pa_tnc_attribute;
}


