/*
 * Copyright (C) 2011 Andreas Steffen
 *
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

#include "ita_comp_ima.h"
#include "ita_comp_func_name.h"

#include "libpts.h"
#include "pts/components/pts_component.h"

#include <debug.h>
#include <pen/pen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define IMA_SECURITY_DIR			"/sys/kernel/security/tpm0/"
#define IMA_BIOS_MEASUREMENT_PATH	IMA_SECURITY_DIR "binary_bios_measurements"
#define IMA_PCR_MAX					16

typedef struct pts_ita_comp_ima_t pts_ita_comp_ima_t;

/**
 * Private data of a pts_ita_comp_ima_t object.
 *
 */
struct pts_ita_comp_ima_t {

	/**
	 * Public pts_component_t interface.
	 */
	pts_component_t public;

	/**
	 * Component Functional Name
	 */
	pts_comp_func_name_t *name;

	/**
	 * AIK keyid
	 */
	chunk_t keyid;

	/**
	 * Sub-component depth
	 */
	u_int32_t depth;

	/**
	 * PTS measurement database
	 */
	pts_database_t *pts_db;

	/**
	 * Primary key for Component Functional Name database entry
	 */
	int cid;

	/**
	 * Primary key for AIK database entry
	 */
	int kid;

	/**
	 * Component is registering measurements 
	 */
	bool is_registering;

	/**
     * IMA BIOS measurement time
	 */
	time_t bios_measurement_time;

	/**
     * IMA BIOS measurements
	 */
	linked_list_t *list;

	/**
	 * Expected measurement count
	 */
	int count;

	/**
	 * Measurement sequence number
	 */
	int seq_no;

	/**
	 * Shadow PCR registers
	 */
	chunk_t pcrs[IMA_PCR_MAX];
};

typedef struct entry_t entry_t;

/**
 * Linux IMA measurement entry
 */
struct entry_t {

	/**
	 * PCR register
	 */
	u_int32_t pcr;

	/**
	 * SHA1 measurement hash
	 */	
	chunk_t measurement;
};

/**
 * Free an entry_t object
 */
static void free_entry(entry_t *this)
{
	free(this->measurement.ptr);
	free(this);
}

/**
 * Load a PCR measurement file and determine the creation date
 */
static bool load_measurements(char *file, linked_list_t *list, time_t *created)
{
	u_int32_t pcr, num, len;
	entry_t *entry;
	struct stat st;
	ssize_t res;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_PTS, "  opening '%s' failed: %s", file, strerror(errno));
		return FALSE;
	}

	if (fstat(fd, &st) == -1)
	{
		DBG1(DBG_PTS, "  getting statistics of '%s' failed: %s", file,
			 strerror(errno));
		close(fd);
		return FALSE;
	}
	*created = st.st_ctime;

	while (TRUE)
	{
		res = read(fd, &pcr, 4);
		if (res == 0)
		{
			DBG2(DBG_PTS, "loaded bios measurements '%s' (%d entries)",
						   file, list->get_count(list));
			close(fd);
			return TRUE;
		}

		entry = malloc_thing(entry_t);
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
		list->insert_last(list, entry);
	}

	DBG1(DBG_PTS, "loading bios measurements '%s' failed: %s",
				   file, strerror(errno));
	close(fd);
	return FALSE;
}

METHOD(pts_component_t, get_comp_func_name, pts_comp_func_name_t*,
	pts_ita_comp_ima_t *this)
{
	return this->name;
}

METHOD(pts_component_t, get_evidence_flags, u_int8_t,
	pts_ita_comp_ima_t *this)
{
	return PTS_REQ_FUNC_COMP_EVID_PCR;
}

METHOD(pts_component_t, get_depth, u_int32_t,
	pts_ita_comp_ima_t *this)
{
	return this->depth;
}

METHOD(pts_component_t, measure, status_t,
	pts_ita_comp_ima_t *this, pts_t *pts, pts_comp_evidence_t **evidence)
{
	pts_comp_evidence_t *evid;
	chunk_t pcr_before, pcr_after;
	pts_pcr_transform_t pcr_transform;
	pts_meas_algorithms_t hash_algo;
	size_t pcr_len;
	entry_t *entry;
	hasher_t *hasher;

	hash_algo = PTS_MEAS_ALGO_SHA1;
	pcr_len = pts->get_pcr_len(pts);   
	pcr_transform = pts_meas_algo_to_pcr_transform(hash_algo, pcr_len);

	if (this->list->get_count(this->list) == 0)
	{
		if (!load_measurements(IMA_BIOS_MEASUREMENT_PATH, this->list,
							   &this->bios_measurement_time))
		{
			return FAILED;
		}
	}
	
	if (this->list->remove_first(this->list, (void**)&entry) != SUCCESS)
	{
		DBG1(DBG_PTS, "could not retrieve measurement entry");
		return FAILED;
	}
	
	pcr_before = chunk_clone(this->pcrs[entry->pcr]);
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	hasher->get_hash(hasher, pcr_before, NULL);
	hasher->get_hash(hasher, entry->measurement, this->pcrs[entry->pcr].ptr);
	hasher->destroy(hasher);

	pcr_after = chunk_clone(this->pcrs[entry->pcr]);

	evid = *evidence = pts_comp_evidence_create(this->name->clone(this->name),
							this->depth, entry->pcr, hash_algo, pcr_transform,
							this->bios_measurement_time, entry->measurement);
	evid->set_pcr_info(evid, pcr_before, pcr_after);

	free(entry);

	return (this->list->get_count(this->list)) ? NEED_MORE : SUCCESS;
}

METHOD(pts_component_t, verify, status_t,
	pts_ita_comp_ima_t *this, pts_t *pts, pts_comp_evidence_t *evidence)
{
	bool has_pcr_info;
	u_int32_t extended_pcr, vid, name;
	enum_name_t *names;
	pts_meas_algorithms_t algo;
	pts_pcr_transform_t transform;
	time_t measurement_time;
	chunk_t measurement, pcr_before, pcr_after;

	measurement = evidence->get_measurement(evidence, &extended_pcr,
								&algo, &transform, &measurement_time);

	if (!this->keyid.ptr)
	{
		if (!pts->get_aik_keyid(pts, &this->keyid))
		{
			return FAILED;
		}
		this->keyid = chunk_clone(this->keyid);

		if (!this->pts_db)
		{
			DBG1(DBG_PTS, "pts database not available");
			return FAILED;
		}
		if (this->pts_db->get_comp_measurement_count(this->pts_db,
							this->name, this->keyid, algo,
							&this->cid, &this->kid, &this->count) != SUCCESS)
		{
			return FAILED;
		}
		vid = this->name->get_vendor_id(this->name);
		name = this->name->get_name(this->name);
		names = pts_components->get_comp_func_names(pts_components, vid);

		if (this->count)
		{
			DBG1(DBG_PTS, "checking %d %N '%N' functional component evidence "
				 "measurements", this->count, pen_names, vid, names, name);
		}
		else
		{
			DBG1(DBG_PTS, "registering %N '%N' functional component evidence "
				 "measurements", pen_names, vid, names, name);
			this->is_registering = TRUE;
		}
	}

	if (this->is_registering)
	{
		if (this->pts_db->insert_comp_measurement(this->pts_db, measurement,
										this->cid, this->kid, ++this->seq_no,
										extended_pcr, algo) != SUCCESS)
		{
			return FAILED;
		}
		this->count = this->seq_no + 1;
	}
	else
	{
		if (this->pts_db->check_comp_measurement(this->pts_db, measurement,
										this->cid, this->kid, ++this->seq_no,
										extended_pcr, algo) != SUCCESS)
		{
			return FAILED;
		}
	}

	has_pcr_info = evidence->get_pcr_info(evidence, &pcr_before, &pcr_after);
	if (has_pcr_info)
	{
		if (!pts->add_pcr(pts, extended_pcr, pcr_before, pcr_after))
		{
			return FAILED;
		}
	}

	return (this->seq_no < this->count) ? NEED_MORE : SUCCESS;
}

METHOD(pts_component_t, check_off_registrations, bool,
	pts_ita_comp_ima_t *this)
{
	u_int32_t vid, name;
	enum_name_t *names;
		
	if (!this->is_registering)
	{
		return FALSE;
	}

	/* Finalize registration */
	this->is_registering = FALSE;

	vid = this->name->get_vendor_id(this->name);
	name = this->name->get_name(this->name);
	names = pts_components->get_comp_func_names(pts_components, vid);
	DBG1(DBG_PTS, "registered %d %N '%N' functional component evidence "
				  "measurements", this->seq_no, pen_names, vid, names, name);
	return TRUE;
}

METHOD(pts_component_t, destroy, void,
	pts_ita_comp_ima_t *this)
{
	int i, count;
	u_int32_t vid, name;
	enum_name_t *names;

	for (i = 0; i < IMA_PCR_MAX; i++)
	{
		free(this->pcrs[i].ptr);
	}
	if (this->is_registering)
	{
		count = this->pts_db->delete_comp_measurements(this->pts_db,
													   this->cid, this->kid);
		vid = this->name->get_vendor_id(this->name);
		name = this->name->get_name(this->name);
		names = pts_components->get_comp_func_names(pts_components, vid);
		DBG1(DBG_PTS, "deleted %d registered %N '%N' functional component "
			 "evidence measurements", count, pen_names, vid, names, name);
	}
	this->list->destroy_function(this->list, (void *)free_entry);
	this->name->destroy(this->name);
	free(this->keyid.ptr);
	free(this);
}

/**
 * See header
 */
pts_component_t *pts_ita_comp_ima_create(u_int8_t qualifier, u_int32_t depth,
										 pts_database_t *pts_db)
{
	pts_ita_comp_ima_t *this;
	int i;

	INIT(this,
		.public = {
			.get_comp_func_name = _get_comp_func_name,
			.get_evidence_flags = _get_evidence_flags,
			.get_depth = _get_depth,
			.measure = _measure,
			.verify = _verify,
			.check_off_registrations = _check_off_registrations,
			.destroy = _destroy,
		},
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_IMA,
										  qualifier),
		.depth = depth,
		.pts_db = pts_db,
		.list = linked_list_create(),
	);

	for (i = 0; i < IMA_PCR_MAX; i++)
	{
		this->pcrs[i] = chunk_alloc(HASH_SIZE_SHA1);
		memset(this->pcrs[i].ptr, 0x00, HASH_SIZE_SHA1);
	}
	return &this->public;
}

