/*
 * Copyright (C) 2018 Tobias Brunner
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

#include <library.h>
#include <utils/debug.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	identification_t *id;
	chunk_t chunk;

	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ids");

	chunk = chunk_create((u_char*)buf, len);
	id = identification_create_from_data(chunk);
	DESTROY_IF(id);

	library_deinit();
	return 0;
}
