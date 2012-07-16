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

#define SECURITY_DIR				"/sys/kernel/security/"
#define IMA_BIOS_MEASUREMENTS		SECURITY_DIR "tpm0/binary_bios_measurements"
#define IMA_RUNTIME_MEASUREMENTS	SECURITY_DIR "ima/binary_runtime_measurements"
#define IMA_EVENT_NAME_LEN_MAX		255
#define IMA_PCR						10
#define IMA_PCR_MAX					16
#define IMA_TYPE_LEN				3

typedef struct pts_ita_comp_ima_t pts_ita_comp_ima_t;
typedef struct bios_entry_t bios_entry_t;
typedef struct ima_entry_t ima_entry_t;
typedef enum ima_state_t ima_state_t;

enum ima_state_t {
	IMA_STATE_INIT,
	IMA_STATE_BIOS,
	IMA_STATE_BOOT_AGGREGATE,
	IMA_STATE_RUNTIME,
	IMA_STATE_END
};

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
	 * Measurement sequence number
	 */
	int seq_no;

	/**
	 * Expected IMA BIOS measurement count
	 */
	int count;

	/**
     * IMA BIOS measurements
	 */
	linked_list_t *bios_list;

	/**
     * IMA runtime file measurements
	 */
	linked_list_t *ima_list;

	/**
	 * Shadow PCR registers
	 */
	chunk_t pcrs[IMA_PCR_MAX];

	/**
	 * IMA measurement time
	 */
	time_t measurement_time;

	/**
	 * IMA state machine
	 */
	ima_state_t state;

	/**
	 * Hasher used to extend emulated PCRs
	 */
	hasher_t *hasher;

};

/**
 * Linux IMA BIOS measurement entry
 */
struct bios_entry_t {

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
 * Linux IMA runtime file measurement entry
 */
struct ima_entry_t {

	/**
	 * SHA1 measurement hash
	 */
	chunk_t measurement;

	/**
	 * SHA1 file measurement thash
	 */
	chunk_t file_measurement;

	/**
	 * absolute path of executable files or basename of dynamic libraries
	 */
	char *filename;
};

/**
 * Free a bios_entry_t object
 */
static void free_bios_entry(bios_entry_t *this)
{
	free(this->measurement.ptr);
	free(this);
}

/**
 * Free an ima_entry_t object
 */
static void free_ima_entry(ima_entry_t *this)
{
	free(this->measurement.ptr);
	free(this->file_measurement.ptr);
	free(this->filename);
	free(this);
}

/**
 * Load a PCR measurement file and determine the creation date
 */
static bool load_bios_measurements(char *file, linked_list_t *list,
								   time_t *created)
{
	u_int32_t pcr, num, len;
	bios_entry_t *entry;
	struct stat st;
	ssize_t res;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_PTS, "opening '%s' failed: %s", file, strerror(errno));
		return FALSE;
	}

	if (fstat(fd, &st) == -1)
	{
		DBG1(DBG_PTS, "getting statistics of '%s' failed: %s", file,
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
		list->insert_last(list, entry);
	}

	DBG1(DBG_PTS, "loading bios measurements '%s' failed: %s", file,
		 strerror(errno));
	close(fd);
	return FALSE;
}

/**
 * Load an IMA runtime measurement file and determine the creation and
 * update dates
 */
static bool load_runtime_measurements(char *file, linked_list_t *list,
									 time_t *created)
{
	u_int32_t pcr, len;
	ima_entry_t *entry;
	char type[IMA_TYPE_LEN];
	struct stat st;
	ssize_t res;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1(DBG_PTS, "opening '%s' failed: %s", file, strerror(errno));
		return TRUE;
	}

	if (fstat(fd, &st) == -1)
	{
		DBG1(DBG_PTS, "getting statistics of '%s' failed: %s", file,
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
			DBG2(DBG_PTS, "loaded ima measurements '%s' (%d entries)",
				 file, list->get_count(list));
			close(fd);
			return TRUE;
		}

		entry = malloc_thing(ima_entry_t);
		entry->measurement = chunk_alloc(HASH_SIZE_SHA1);
		entry->file_measurement = chunk_alloc(HASH_SIZE_SHA1);
		entry->filename = NULL;

		if (res != 4 || pcr != IMA_PCR)
		{
			break;
		}
		if (read(fd, entry->measurement.ptr, HASH_SIZE_SHA1) != HASH_SIZE_SHA1)
		{
			break;
		}
		if (read(fd, &len, 4) != 4 || len != IMA_TYPE_LEN)
		{
			break;
		}
		if (read(fd, type, IMA_TYPE_LEN) != IMA_TYPE_LEN ||
			memcmp(type, "ima", IMA_TYPE_LEN))
		{
			break;
		}
		if (read(fd, entry->file_measurement.ptr, HASH_SIZE_SHA1) != HASH_SIZE_SHA1)
		{
			break;
		}
		if (read(fd, &len, 4) != 4)
		{
			break;
		}
		entry->filename = malloc(len + 1);
		if (read(fd, entry->filename, len) != len)
		{
			break;
		}
		entry->filename[len] = '\0';

		list->insert_last(list, entry);
	}

	DBG1(DBG_PTS, "loading ima measurements '%s' failed: %s",
		 file, strerror(errno));
	close(fd);
	return FALSE;
}

/**
 * Extend measurement into PCR an create evidence
 */
pts_comp_evidence_t* extend_pcr(pts_ita_comp_ima_t* this, u_int32_t pcr,
								chunk_t measurement)
{
	size_t pcr_len;
	pts_pcr_transform_t pcr_transform;
	pts_meas_algorithms_t hash_algo;
	pts_comp_evidence_t *evidence;
	chunk_t pcr_before, pcr_after;

	hash_algo = PTS_MEAS_ALGO_SHA1;
	pcr_len = HASH_SIZE_SHA1;
	pcr_transform = pts_meas_algo_to_pcr_transform(hash_algo, pcr_len);
	pcr_before = chunk_clone(this->pcrs[pcr]);
	if (!this->hasher->get_hash(this->hasher, pcr_before, NULL) ||
		!this->hasher->get_hash(this->hasher, measurement, this->pcrs[pcr].ptr))
	{
		DBG1(DBG_PTS, "PCR%d was not extended due to a hasher problem", pcr);
	}
	pcr_after = chunk_clone(this->pcrs[pcr]);

	evidence = pts_comp_evidence_create(this->name->clone(this->name),
								this->depth, pcr, hash_algo, pcr_transform,
								this->measurement_time, measurement);
	evidence->set_pcr_info(evidence, pcr_before, pcr_after);

	return evidence;
}

/**
 * Compute and check boot aggregate value by hashing PCR0 to PCR7
 */
void check_boot_aggregate(pts_ita_comp_ima_t *this, chunk_t measurement)
{
	u_int32_t pcr;
	u_char pcr_buffer[HASH_SIZE_SHA1];
	u_char boot_aggregate_name[] = "boot_aggregate";
	u_char filename_buffer[IMA_EVENT_NAME_LEN_MAX + 1];
	chunk_t boot_aggregate, file_name;
	bool pcr_ok = TRUE;

	/* See Linux kernel header: security/integrity/ima/ima.h */
	boot_aggregate = chunk_create(pcr_buffer, sizeof(pcr_buffer));
	memset(filename_buffer, 0, sizeof(filename_buffer));
	strcpy(filename_buffer, boot_aggregate_name);
	file_name = chunk_create(filename_buffer, sizeof(filename_buffer));

	for (pcr = 0; pcr < 8 && pcr_ok; pcr++)
	{
		pcr_ok = this->hasher->get_hash(this->hasher, this->pcrs[pcr], NULL);
	}
	if (!pcr_ok ||
		!this->hasher->get_hash(this->hasher, chunk_empty, pcr_buffer) ||
		!this->hasher->get_hash(this->hasher, boot_aggregate, NULL) ||
		!this->hasher->get_hash(this->hasher, file_name, pcr_buffer))
	{
		DBG1(DBG_PTS, "failed to compute boot aggregate value");
		return;
	}
	DBG1(DBG_PTS, "boot aggregate value is %scorrect",
		 chunk_equals(boot_aggregate, measurement) ? "":"in");
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
	pts_ita_comp_ima_t *this, pts_t *pts, pts_comp_evidence_t **evidence,
	pts_file_meas_t **measurements)
{
	bios_entry_t *bios_entry;
	ima_entry_t *ima_entry, *entry;
	status_t status;
	enumerator_t *e;
	pts_file_meas_t *file_meas;

	*measurements = NULL;

	switch (this->state)
	{
		case IMA_STATE_INIT:
			if (!load_bios_measurements(IMA_BIOS_MEASUREMENTS, this->bios_list,
				&this->measurement_time))
			{
				return FAILED;
			}
			this->state = IMA_STATE_BIOS;
			/* fall through to next state */
		case IMA_STATE_BIOS:
			status = this->bios_list->remove_first(this->bios_list,
												  (void**)&bios_entry);
			if (status != SUCCESS)
			{
				DBG1(DBG_PTS, "could not retrieve bios measurement entry");
				return status;
			}
			*evidence = extend_pcr(this, bios_entry->pcr,
										 bios_entry->measurement);
			free(bios_entry);
	
			/* break if still some BIOS measurements are left */
			if (this->bios_list->get_count(this->bios_list))
			{
				break;
			}

			/* check if IMA runtime measurements are enabled */
			if (!load_runtime_measurements(IMA_RUNTIME_MEASUREMENTS,
							this->ima_list, &this->measurement_time))
			{
				return FAILED;
			}

			this->state = this->ima_list->get_count(this->ima_list) ?
									IMA_STATE_BOOT_AGGREGATE : IMA_STATE_END;
			break;
		case IMA_STATE_BOOT_AGGREGATE:
		case IMA_STATE_RUNTIME:
			status = this->ima_list->remove_first(this->ima_list,
												 (void**)&ima_entry);
			if (status != SUCCESS)
			{
				DBG1(DBG_PTS, "could not retrieve ima measurement entry");
				return status;
			}
			*evidence = extend_pcr(this, IMA_PCR, ima_entry->measurement);

			if (this->state == IMA_STATE_BOOT_AGGREGATE)
			{
				check_boot_aggregate(this, ima_entry->measurement);

				if (this->ima_list->get_count(this->ima_list))
				{
					/* extract file measurements */
					file_meas = pts_file_meas_create(0);

					e = this->ima_list->create_enumerator(this->ima_list);
					while (e->enumerate(e, &entry))
					{
						file_meas->add(file_meas, entry->filename,
												  entry->file_measurement);
					}
					e->destroy(e);
					*measurements = file_meas;
				}
			}

			free(ima_entry->file_measurement.ptr);
			free(ima_entry->filename);
			free(ima_entry);
			this->state = this->ima_list->get_count(this->ima_list) ?
									IMA_STATE_RUNTIME : IMA_STATE_END;
			break;
		case IMA_STATE_END:
			break;
	}
	
	return (this->state == IMA_STATE_END) ? SUCCESS : NEED_MORE;
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
	status_t status;

	measurement = evidence->get_measurement(evidence, &extended_pcr,
								&algo, &transform, &measurement_time);

	switch (this->state)
	{
		case IMA_STATE_INIT:
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
			status = this->pts_db->get_comp_measurement_count(this->pts_db,
									this->name, this->keyid, algo,
									&this->cid, &this->kid, &this->count);
			if (status != SUCCESS)
			{
				return status;
			}
			vid = this->name->get_vendor_id(this->name);
			name = this->name->get_name(this->name);
			names = pts_components->get_comp_func_names(pts_components, vid);

			if (this->count)
			{
				DBG1(DBG_PTS, "checking %d %N '%N' functional component "
							  "evidence measurements", this->count, pen_names,
							   vid, names, name);
			}
			else
			{
				DBG1(DBG_PTS, "registering %N '%N' functional component "
							  "evidence measurements", pen_names, vid, names,
							   name);
				this->is_registering = TRUE;
			}
			this->state = IMA_STATE_BIOS;
			/* fall through to next state */
		case IMA_STATE_BIOS:
			if (extended_pcr != IMA_PCR)
			{
				if (this->is_registering)
				{
					status = this->pts_db->insert_comp_measurement(this->pts_db,
											measurement, this->cid, this->kid,
											++this->seq_no,	extended_pcr, algo);
					if (status != SUCCESS)
					{
						return status;
					}
					this->count = this->seq_no + 1;
				}
				else
				{
					status = this->pts_db->check_comp_measurement(this->pts_db,
											measurement, this->cid, this->kid,
											++this->seq_no,	extended_pcr, algo);
					if (status != SUCCESS)
					{
						return status;
					}
				}
				break;
			}
			this->state = IMA_STATE_BOOT_AGGREGATE;
			/* fall through to next state */
		case IMA_STATE_BOOT_AGGREGATE:
			this->state = IMA_STATE_RUNTIME;
			break;
		case IMA_STATE_RUNTIME:
			break;
		case IMA_STATE_END:
			break;
	}

	has_pcr_info = evidence->get_pcr_info(evidence, &pcr_before, &pcr_after);
	if (has_pcr_info)
	{
		if (!pts->add_pcr(pts, extended_pcr, pcr_before, pcr_after))
		{
			return FAILED;
		}
	}

	return SUCCESS;
}

METHOD(pts_component_t, finalize, bool,
	pts_ita_comp_ima_t *this)
{
	u_int32_t vid, name;
	enum_name_t *names;
		
	vid = this->name->get_vendor_id(this->name);
	name = this->name->get_name(this->name);
	names = pts_components->get_comp_func_names(pts_components, vid);

	if (this->is_registering)
	{
		/* close registration */
		this->is_registering = FALSE;

		DBG1(DBG_PTS, "registered %d %N '%N' functional component evidence "
					  "measurements", this->seq_no, pen_names, vid, names, name);
	}
	else if (this->seq_no < this->count)
	{
		DBG1(DBG_PTS, "%d of %d %N '%N' functional component evidence "
					  "measurements missing", this->count - this->seq_no,
					   this->count, pen_names, vid, names, name);
		return FALSE;
	}

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
	this->bios_list->destroy_function(this->bios_list, (void *)free_bios_entry);
	this->ima_list->destroy_function(this->ima_list, (void *)free_ima_entry);
	this->name->destroy(this->name);
	this->hasher->destroy(this->hasher);
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
			.finalize = _finalize,
			.destroy = _destroy,
		},
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_IMA,
										  qualifier),
		.depth = depth,
		.pts_db = pts_db,
		.bios_list = linked_list_create(),
		.ima_list = linked_list_create(),
		.hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1),
	);

	for (i = 0; i < IMA_PCR_MAX; i++)
	{
		this->pcrs[i] = chunk_alloc(HASH_SIZE_SHA1);
		memset(this->pcrs[i].ptr, 0x00, HASH_SIZE_SHA1);
	}
	return &this->public;
}

