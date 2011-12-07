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

#include "ita_comp_tboot.h"
#include "ita_comp_func_name.h"

#include "libpts.h"
#include "pts/components/pts_component.h"

#include <debug.h>
#include <pen/pen.h>
#include <utils/lexparser.h>

#include <sys/stat.h>
#include <errno.h>

#define TBOOT_PCR_MIN					17
#define TBOOT_PCR_COUNT					2
#define TBOOT_LOG_MEAS_BEGIN			16000

typedef struct pts_ita_comp_tboot_t pts_ita_comp_tboot_t;

/**
 * Private data of a pts_ita_comp_tboot_t object.
 *
 */
struct pts_ita_comp_tboot_t {

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
	 * Time of TBOOT measurement
	 */
	time_t measurement_time;

	/**
	 * Expected measurement count
	 */
	int count;

	/**
	 * Measurement sequence number
	 */
	int seq_no;

	/**
     * tboot measurements
	 */
	linked_list_t *list;

};

typedef struct entry_t entry_t;

/**
 * tboot measurement entry
 */
struct entry_t {

	/**
	 * PCR register
	 */
	u_int32_t pcr;

	/**
	 * PCR before value
	 */
	chunk_t pcr_before;

	/**
	 * PCR after value
	 */
	chunk_t pcr_after;

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
	free(this->pcr_before.ptr);
	free(this->pcr_after.ptr);
	free(this);
}

/**
 * Load a tboot logfile and determine the creation date
 */
static bool load_measurements(linked_list_t *list, time_t *created)
{
	char *file, *buffer;
	u_int32_t i, j, tboot_log_len;
	entry_t *entry;
	struct stat st;
	FILE *fp;

	file = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.tboot_log", NULL);
	if (!file)
	{
		DBG1(DBG_PTS, "tboot log file unavailable, please configure tboot_log");
		return FALSE;
	}

	if ((fp = fopen(file, "r")) == NULL)
	{
		DBG1(DBG_PTS, "  opening '%s' failed: %s", file, strerror(errno));
		return FALSE;
	}

	if (stat(file, &st))
	{
		DBG1(DBG_PTS, "  getting statistics of '%s' failed: %s", file,
			 strerror(errno));
		fclose(fp);
		return FALSE;
	}
	*created = st.st_ctime;

	fseek(fp, 0, SEEK_END);
	tboot_log_len = ftell(fp);
	fseek(fp, TBOOT_LOG_MEAS_BEGIN, SEEK_SET);

	buffer = (char*) malloc (sizeof(char)*tboot_log_len);
	if (!fread(buffer, 1, tboot_log_len - TBOOT_LOG_MEAS_BEGIN, fp))
	{
		DBG1(DBG_PTS, "unable to read tboot log file '%s'", file);
		fclose(fp);
		return FALSE;
	}

	fclose(fp);
	DBG2(DBG_PTS, "loaded tboot log file from '%s'", file);
	
	for (i = 0 ; i < TBOOT_PCR_COUNT ; i++)
	{
		char pcr_index[10];
		char hex[HASH_SIZE_SHA1*3];
		char const *p;
		chunk_t temp;

		entry = malloc_thing(entry_t);
		entry->measurement = chunk_alloc(HASH_SIZE_SHA1);
		entry->pcr_before = chunk_alloc(HASH_SIZE_SHA1);
		entry->pcr_after = chunk_alloc(HASH_SIZE_SHA1);
		entry->pcr = TBOOT_PCR_MIN + i;

		p = buffer;
		sprintf(pcr_index, "PCR %d", entry->pcr);
		
		/* measurement, pcr before and after value for each tboot PCR */
		for (j = 0 ; j < 3 ; j++)
		{
			p = strstr(p, pcr_index);
			if (!p)
			{
				DBG1(DBG_PTS, "unable to read measurement for '%s'", pcr_index);
				free(entry);
				free(buffer);
				return FALSE;
			}
			
			/* skip the index ('PCR 17: ') and copy actual hex */
			strncpy(hex, p + 8, HASH_SIZE_SHA1*3);
			hex[HASH_SIZE_SHA1*3 - 1] = '\0';
			temp = chunk_from_hex(chunk_create(hex, HASH_SIZE_SHA1*3), temp.ptr);

			switch (j)
			{
				case 0:
					memcpy(entry->measurement.ptr,
						temp.ptr + (temp.len - HASH_SIZE_SHA1), HASH_SIZE_SHA1);
					break;
				case 1:
					memcpy(entry->pcr_before.ptr,
						temp.ptr + (temp.len - HASH_SIZE_SHA1), HASH_SIZE_SHA1);
					break;
				case 2:
					memcpy(entry->pcr_after.ptr,
						temp.ptr + (temp.len - HASH_SIZE_SHA1), HASH_SIZE_SHA1);
					break;
			}
			chunk_clear(&temp);
			p++;
		}
		list->insert_last(list, entry);
	}

	free(buffer);
	return TRUE;
}

METHOD(pts_component_t, get_comp_func_name, pts_comp_func_name_t*,
	pts_ita_comp_tboot_t *this)
{
	return this->name;
}

METHOD(pts_component_t, get_evidence_flags, u_int8_t,
	pts_ita_comp_tboot_t *this)
{
	return PTS_REQ_FUNC_COMP_EVID_PCR;
}

METHOD(pts_component_t, get_depth, u_int32_t,
	pts_ita_comp_tboot_t *this)
{
	return this->depth;
}

METHOD(pts_component_t, measure, status_t,
	pts_ita_comp_tboot_t *this, pts_t *pts, pts_comp_evidence_t **evidence)
{
	pts_comp_evidence_t *evid;
	pts_pcr_transform_t pcr_transform;
	pts_meas_algorithms_t hash_algo;
	size_t pcr_len;
	entry_t *entry;

	hash_algo = PTS_MEAS_ALGO_SHA1;
	pcr_len = pts->get_pcr_len(pts);
	pcr_transform = pts_meas_algo_to_pcr_transform(hash_algo, pcr_len);

	if (this->list->get_count(this->list) == 0)
	{
		if (!load_measurements(this->list,
							   &this->measurement_time))
		{
			return FAILED;
		}
	}

	if (this->list->remove_first(this->list, (void**)&entry) != SUCCESS)
	{
		DBG1(DBG_PTS, "could not retrieve measurement entry");
		return FAILED;
	}

	evid = *evidence = pts_comp_evidence_create(this->name->clone(this->name),
							this->depth, entry->pcr, hash_algo, pcr_transform,
							this->measurement_time, entry->measurement);
	evid->set_pcr_info(evid, entry->pcr_before, entry->pcr_after);

	free(entry);

	return (this->list->get_count(this->list)) ? NEED_MORE : SUCCESS;
}

METHOD(pts_component_t, verify, status_t,
	pts_ita_comp_tboot_t *this, pts_t *pts, pts_comp_evidence_t *evidence)
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
	pts_ita_comp_tboot_t *this)
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
	   pts_ita_comp_tboot_t *this)
{
	int count;
	u_int32_t vid, name;
	enum_name_t *names;

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
pts_component_t *pts_ita_comp_tboot_create(u_int8_t qualifier, u_int32_t depth,
										   pts_database_t *pts_db)
{
	pts_ita_comp_tboot_t *this;

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
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_TBOOT,
										  qualifier),
		.depth = depth,
		.pts_db = pts_db,
		.list = linked_list_create(),
	);

	return &this->public;
}

