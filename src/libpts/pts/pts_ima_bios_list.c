/*
 * Copyright (C) 2011-2014 Andreas Steffen
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

#include "pts_ima_bios_list.h"

#include <utils/debug.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

typedef struct private_pts_ima_bios_list_t private_pts_ima_bios_list_t;
typedef struct bios_entry_t bios_entry_t;

/**
 * Private data of a pts_ima_bios_list_t object.
 *
 */
struct private_pts_ima_bios_list_t {

	/**
	 * Public pts_ima_bios_list_t interface.
	 */
	pts_ima_bios_list_t public;

	/**
	 * List of BIOS measurement entries
	 */
	linked_list_t *list;

	/**
	 * Time when BIOS measurements were taken
	 */
	time_t creation_time;

};

/**
 * Linux IMA BIOS measurement entry
 */
struct bios_entry_t {

	/**
	 * PCR register
	 */
	uint32_t pcr;

	/**
	 * SHA1 measurement hash
	 */
	chunk_t measurement;
};

/**
 * Free a bios_entry_t object
 */
static void free_bios_entry(bios_entry_t *this)
{
	free(this->measurement.ptr);
	free(this);
}

METHOD(pts_ima_bios_list_t, get_time, time_t,
	private_pts_ima_bios_list_t *this)
{
	return this->creation_time;
}

METHOD(pts_ima_bios_list_t, get_count, int,
	private_pts_ima_bios_list_t *this)
{
	return this->list->get_count(this->list);
}

METHOD(pts_ima_bios_list_t, get_next, status_t,
	private_pts_ima_bios_list_t *this, uint32_t *pcr, chunk_t *measurement)
{
	bios_entry_t *entry;
	status_t status;

	status = this->list->remove_first(this->list, (void**)&entry);
	*pcr = entry->pcr;
	*measurement = entry->measurement;
	free(entry);

	return status;
}

METHOD(pts_ima_bios_list_t, destroy, void,
	private_pts_ima_bios_list_t *this)
{
	this->list->destroy_function(this->list, (void *)free_bios_entry);
	free(this);
}

/**
 * See header
 */
pts_ima_bios_list_t* pts_ima_bios_list_create(char *file)
{
	private_pts_ima_bios_list_t *this;
	uint32_t pcr, num, len;
	bios_entry_t *entry;
	struct stat st;
	ssize_t res;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_PTS, "opening '%s' failed: %s", file, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) == -1)
	{
		DBG1(DBG_PTS, "getting statistics of '%s' failed: %s", file,
			 strerror(errno));
		close(fd);
		return FALSE;
	}

	INIT(this,
		.public = {
			.get_time = _get_time,
			.get_count = _get_count,
			.get_next = _get_next,
			.destroy = _destroy,
		},
		.creation_time = st.st_ctime,
		.list = linked_list_create(),
	);

	while (TRUE)
	{
		res = read(fd, &pcr, 4);
		if (res == 0)
		{
			DBG2(DBG_PTS, "loaded bios measurements '%s' (%d entries)",
				 file, this->list->get_count(this->list));
			close(fd);
			return &this->public;
		}

		entry = malloc_thing(bios_entry_t);
		entry->pcr = pcr;
		entry->measurement = chunk_alloc(HASH_SIZE_SHA1);

		if (res != 4)
		{
			break;
		}
		if (read(fd, &num, 4) != 4)
		{
			break;
		}
		if (read(fd, entry->measurement.ptr, HASH_SIZE_SHA1) != HASH_SIZE_SHA1)
		{
			break;
		}
		if (read(fd, &len, 4) != 4)
		{
			break;
		}
		if (lseek(fd, len, SEEK_CUR) == -1)
		{
			break;
		}
		this->list->insert_last(this->list, entry);
	}

	DBG1(DBG_PTS, "loading bios measurements '%s' failed: %s", file,
		 strerror(errno));
	free_bios_entry(entry);
	close(fd);
	destroy(this);

	return NULL;
}
