/*
 * Copyright (C) 2018 Tobias Brunner
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

#include <library.h>
#include <utils/debug.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ids");
	atexit(library_deinit);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	identification_t *id, *clone;
	enumerator_t *part_enum;
	chunk_t chunk, data;
	id_part_t part;
	char str_buf[BUF_LEN], min_buf[3];

	chunk = chunk_create((u_char*)buf, len);
	id = identification_create_from_data(chunk);
	if (id)
	{
		id->hash(id, 0U);
		id->equals(id, id);
		id->matches(id, id);
		id->contains_wildcards(id);

		part_enum = id->create_part_enumerator(id);
		if (part_enum)
		{
			while (part_enum->enumerate(part_enum, &part, &data));
			part_enum->destroy(part_enum);
		}

		clone = id->clone(id);
		clone->destroy(clone);
	}

	snprintf(str_buf, sizeof(str_buf), "%Y", id);
	snprintf(min_buf, sizeof(min_buf), "%Y", id);
	DESTROY_IF(id);
	return 0;
}
