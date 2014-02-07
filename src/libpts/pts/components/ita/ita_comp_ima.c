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
#include "pts/pts_pcr.h"
#include "pts/components/pts_component.h"

#include <utils/debug.h>
#include <pen/pen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define SECURITY_DIR				"/sys/kernel/security/"
#define IMA_BIOS_MEASUREMENTS		SECURITY_DIR "tpm0/binary_bios_measurements"
#define IMA_RUNTIME_MEASUREMENTS	SECURITY_DIR "ima/binary_runtime_measurements"
#define IMA_PCR						10
#define IMA_TYPE_LEN				3
#define IMA_FILENAME_LEN_MAX	255

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
	 * Primary key for AIK database entry
	 */
	int kid;

	/**
	 * Primary key for IMA BIOS Component Functional Name database entry
	 */
	int bios_cid;

	/**
	 * Primary key for IMA Runtime Component Functional Name database entry
	 */
	int ima_cid;

	/**
	 * Component is registering IMA BIOS measurements
	 */
	bool is_bios_registering;

	/**
	 * Component is registering IMA boot aggregate measurement
	 */
	bool is_ima_registering;

	/**
	 * Measurement sequence number
	 */
	int seq_no;

	/**
	 * Expected IMA BIOS measurement count
	 */
	int bios_count;

	/**
     * IMA BIOS measurements
	 */
	linked_list_t *bios_list;

	/**
     * IMA runtime file measurements
	 */
	linked_list_t *ima_list;

	/**
	 * Whether to send pcr_before and pcr_after info
	 */
	bool pcr_info;

	/**
	 * IMA measurement time
	 */
	time_t measurement_time;

	/**
	 * IMA state machine
	 */
	ima_state_t state;

	/**
	 * Total number of component measurements
	 */
	int count;

	/**
	 * Number of successful component measurements
	 */
	int count_ok;

	/**
	 * Number of unknown component measurements
	 */
	int count_unknown;

	/**
	 * Number of differing component measurements
	 */
	int count_differ;

	/**
	 * Number of failed component measurements
	 */
	int count_failed;

	/**
	 * Reference count
	 */
	refcount_t ref;

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
	free_bios_entry(entry);
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
		if (lseek(fd, HASH_SIZE_SHA1, SEEK_CUR) == -1)
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
	free_ima_entry(entry);
	close(fd);
	return FALSE;
}

/**
 * Extend measurement into PCR an create evidence
 */
static pts_comp_evidence_t* extend_pcr(pts_ita_comp_ima_t* this,
									   u_int8_t qualifier, pts_pcr_t *pcrs,
									   u_int32_t pcr, chunk_t measurement)
{
	size_t pcr_len;
	pts_pcr_transform_t pcr_transform;
	pts_meas_algorithms_t hash_algo;
	pts_comp_func_name_t *name;
	pts_comp_evidence_t *evidence;
	chunk_t pcr_before = chunk_empty, pcr_after = chunk_empty;

	hash_algo = PTS_MEAS_ALGO_SHA1;
	pcr_len = HASH_SIZE_SHA1;
	pcr_transform = pts_meas_algo_to_pcr_transform(hash_algo, pcr_len);

	if (this->pcr_info)
	{
		pcr_before = chunk_clone(pcrs->get(pcrs, pcr));
	}
	pcr_after = pcrs->extend(pcrs, pcr, measurement);
	if (!pcr_after.ptr)
	{
		free(pcr_before.ptr);
		return NULL;
	}
	name = this->name->clone(this->name);
	name->set_qualifier(name, qualifier);
	evidence = pts_comp_evidence_create(name, this->depth, pcr, hash_algo,
			 		pcr_transform, this->measurement_time, measurement);
	if (this->pcr_info)
	{
		pcr_after =chunk_clone(pcrs->get(pcrs, pcr));
		evidence->set_pcr_info(evidence, pcr_before, pcr_after);
	}
	return evidence;
}

/**
 * Compute and check boot aggregate value by hashing PCR0 to PCR7
 */
static bool check_boot_aggregate(pts_pcr_t *pcrs, chunk_t measurement)
{
	u_int32_t i;
	u_char filename_buffer[IMA_FILENAME_LEN_MAX + 1];
	u_char pcr_buffer[HASH_SIZE_SHA1];
	chunk_t file_name, boot_aggregate;
	hasher_t *hasher;
	bool success, pcr_ok = TRUE;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1(DBG_PTS, "%N hasher could not be created",
			 hash_algorithm_short_names, HASH_SHA1);
		return FALSE;
	}
	for (i = 0; i < 8 && pcr_ok; i++)
	{
		pcr_ok = hasher->get_hash(hasher, pcrs->get(pcrs, i), NULL);
	}
	if (pcr_ok)
	{
		boot_aggregate = chunk_create(pcr_buffer, sizeof(pcr_buffer));
		memset(filename_buffer, 0, sizeof(filename_buffer));
		strcpy(filename_buffer, "boot_aggregate");
		file_name = chunk_create (filename_buffer, sizeof(filename_buffer));

		pcr_ok = hasher->get_hash(hasher, chunk_empty, pcr_buffer) &&
				 hasher->get_hash(hasher, boot_aggregate, NULL) &&
				 hasher->get_hash(hasher, file_name, boot_aggregate.ptr);
	}
	hasher->destroy(hasher);

	if (pcr_ok)
	{
		success = chunk_equals(boot_aggregate, measurement);
		DBG1(DBG_PTS, "boot aggregate value is %scorrect",
					   success ? "":"in");
		return success;
	}
	else
	{
		DBG1(DBG_PTS, "failed to compute boot aggregate value");
		return FALSE;
	}
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
	pts_ita_comp_ima_t *this, u_int8_t qualifier, pts_t *pts,
	pts_comp_evidence_t **evidence)
{
	bios_entry_t *bios_entry;
	ima_entry_t *ima_entry;
	pts_pcr_t *pcrs;
	pts_comp_evidence_t *evid = NULL;
	status_t status;

	pcrs = pts->get_pcrs(pts);

	if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
					  PTS_ITA_QUALIFIER_TYPE_TRUSTED))
	{
		switch (this->state)
		{
			case IMA_STATE_INIT:
				if (!load_bios_measurements(IMA_BIOS_MEASUREMENTS,
					this->bios_list, &this->measurement_time))
				{
					return FAILED;
				}
				this->bios_count = this->bios_list->get_count(this->bios_list);
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
				evid = extend_pcr(this, qualifier, pcrs, bios_entry->pcr,
								  bios_entry->measurement);
				free(bios_entry);

				this->state = this->bios_list->get_count(this->bios_list) ?
										IMA_STATE_BIOS : IMA_STATE_INIT;
				break;
			default:
				return FAILED;
		}
	}
	else if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
						   PTS_ITA_QUALIFIER_TYPE_OS))
	{
		switch (this->state)
		{
			case IMA_STATE_INIT:
				if (!load_runtime_measurements(IMA_RUNTIME_MEASUREMENTS,
								this->ima_list, &this->measurement_time))
				{
					return FAILED;
				}
				this->state = IMA_STATE_BOOT_AGGREGATE;
				/* fall through to next state */
			case IMA_STATE_BOOT_AGGREGATE:
			case IMA_STATE_RUNTIME:
				status = this->ima_list->remove_first(this->ima_list,
													 (void**)&ima_entry);
				if (status != SUCCESS)
				{
					DBG1(DBG_PTS, "could not retrieve ima measurement entry");
					return status;
				}
				if (this->state == IMA_STATE_BOOT_AGGREGATE && this->bios_count)
				{
					if (!check_boot_aggregate(pcrs, ima_entry->measurement))
					{
						return FAILED;
					}
				}
				evid = extend_pcr(this, qualifier, pcrs, IMA_PCR,
								  ima_entry->measurement);
				if (evid)
				{
					evid->set_validation(evid, PTS_COMP_EVID_VALIDATION_PASSED,
											   ima_entry->filename);
				}
				free(ima_entry->filename);
				free(ima_entry);

				this->state = this->ima_list->get_count(this->ima_list) ?
									IMA_STATE_RUNTIME : IMA_STATE_END;
				break;
			default:
				return FAILED;
		}
	}
	else
	{
		DBG1(DBG_PTS, "unsupported functional component name qualifier");
		return FAILED;
	}

	*evidence = evid;
	if (!evid)
	{
		return FAILED;
	}

	return (this->state == IMA_STATE_INIT || this->state == IMA_STATE_END) ?
			SUCCESS : NEED_MORE;
}

METHOD(pts_component_t, verify, status_t,
	pts_ita_comp_ima_t *this, u_int8_t qualifier, pts_t *pts,
	pts_comp_evidence_t *evidence)
{
	bool has_pcr_info;
	u_int32_t pcr, vid, name;
	enum_name_t *names;
	pts_meas_algorithms_t algo;
	pts_pcr_transform_t transform;
	pts_pcr_t *pcrs;
	time_t measurement_time;
	chunk_t measurement, pcr_before, pcr_after;
	status_t status;
	char *uri;

	/* some first time initializations */
	if (!this->keyid.ptr)
	{
		if (!pts->get_aik_keyid(pts, &this->keyid))
		{
			DBG1(DBG_PTS, "AIK keyid not available");
			return FAILED;
		}
		this->keyid = chunk_clone(this->keyid);
		if (!this->pts_db)
		{
			DBG1(DBG_PTS, "pts database not available");
			return FAILED;
		}
	}

	pcrs = pts->get_pcrs(pts);
	measurement = evidence->get_measurement(evidence, &pcr,	&algo, &transform,
											&measurement_time);

	if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
					  PTS_ITA_QUALIFIER_TYPE_TRUSTED))
	{
		switch (this->state)
		{
			case IMA_STATE_INIT:
				this->name->set_qualifier(this->name, qualifier);
				status = this->pts_db->get_comp_measurement_count(this->pts_db,
								this->name, this->keyid, algo, &this->bios_cid,
								&this->kid, &this->bios_count);
				this->name->set_qualifier(this->name, PTS_QUALIFIER_UNKNOWN);
				if (status != SUCCESS)
				{
					return status;
				}
				vid = this->name->get_vendor_id(this->name);
				name = this->name->get_name(this->name);
				names = pts_components->get_comp_func_names(pts_components, vid);

				if (this->bios_count)
				{
					DBG1(DBG_PTS, "checking %d %N '%N' BIOS evidence measurements",
								   this->bios_count, pen_names, vid, names, name);
				}
				else
				{
					DBG1(DBG_PTS, "registering %N '%N' BIOS evidence measurements",
								   pen_names, vid, names, name);
					this->is_bios_registering = TRUE;
				}

				this->state = IMA_STATE_BIOS;
				/* fall through to next state */
			case IMA_STATE_BIOS:
				if (this->is_bios_registering)
				{
					status = this->pts_db->insert_comp_measurement(this->pts_db,
										measurement, this->bios_cid, this->kid,
										++this->seq_no,	pcr, algo);
					if (status != SUCCESS)
					{
						return status;
					}
					this->bios_count = this->seq_no + 1;
				}
				else
				{
					status = this->pts_db->check_comp_measurement(this->pts_db,
										measurement, this->bios_cid, this->kid,
										++this->seq_no,	pcr, algo);
					if (status == FAILED)
					{
						return status;
					}
				}
				break;
			default:
				return FAILED;
		}
	}
	else if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
						   PTS_ITA_QUALIFIER_TYPE_OS))
	{
		int ima_count;

		switch (this->state)
		{
			case IMA_STATE_BIOS:
				if (!check_boot_aggregate(pcrs, measurement))
				{
					this->state = IMA_STATE_RUNTIME;
					return FAILED;
				}
				this->state = IMA_STATE_INIT;
				/* fall through to next state */
			case IMA_STATE_INIT:
				this->name->set_qualifier(this->name, qualifier);
				status = this->pts_db->get_comp_measurement_count(this->pts_db,
										this->name, this->keyid, algo,
										&this->ima_cid,	&this->kid, &ima_count);
				this->name->set_qualifier(this->name, PTS_QUALIFIER_UNKNOWN);
				if (status != SUCCESS)
				{
					return status;
				}
				vid = this->name->get_vendor_id(this->name);
				name = this->name->get_name(this->name);
				names = pts_components->get_comp_func_names(pts_components, vid);

				if (ima_count)
				{
					DBG1(DBG_PTS, "checking %N '%N' boot aggregate evidence "
								  "measurement", pen_names, vid, names, name);
					status = this->pts_db->check_comp_measurement(this->pts_db,
													measurement, this->ima_cid,
													this->kid, 1, pcr, algo);
				}
				else
				{
					DBG1(DBG_PTS, "registering %N '%N' boot aggregate evidence "
								   "measurement", pen_names, vid, names, name);
					this->is_ima_registering = TRUE;
					status = this->pts_db->insert_comp_measurement(this->pts_db,
													measurement, this->ima_cid,
										 			this->kid, 1, pcr, algo);
				}
				this->state = IMA_STATE_RUNTIME;

				if (status != SUCCESS)
				{
					return status;
				}
				break;
			case IMA_STATE_RUNTIME:
				this->count++;
				if (evidence->get_validation(evidence, &uri) !=
					PTS_COMP_EVID_VALIDATION_PASSED)
				{
					DBG1(DBG_PTS, "policy URI could no be retrieved");
					this->count_failed++;
					return FAILED;
				}
				status = this->pts_db->check_file_measurement(this->pts_db,
												pts->get_platform_info(pts),
												PTS_MEAS_ALGO_SHA1_IMA,
												measurement, uri);
				switch (status)
				{
					case SUCCESS:
						DBG3(DBG_PTS, "%#B for '%s' is ok",
									   &measurement, uri);
						this->count_ok++;
						break;
					case NOT_FOUND:
						DBG2(DBG_PTS, "%#B for '%s' not found",
									   &measurement, uri);
						this->count_unknown++;
						break;
					case VERIFY_ERROR:
						DBG1(DBG_PTS, "%#B for '%s' differs",
									   &measurement, uri);
						this->count_differ++;
						break;
					case FAILED:
					default:
						DBG1(DBG_PTS, "%#B for '%s' failed",
									   &measurement, uri);
						this->count_failed++;
				}
				break;
			default:
				return FAILED;
		}
	}
	else
	{
		DBG1(DBG_PTS, "unsupported functional component name qualifier");
		return FAILED;
	}

	has_pcr_info = evidence->get_pcr_info(evidence, &pcr_before, &pcr_after);
	if (has_pcr_info)
	{
		if (!chunk_equals(pcr_before, pcrs->get(pcrs, pcr)))
		{
			DBG1(DBG_PTS, "PCR %2u: pcr_before is not equal to register value",
						   pcr);
		}
		if (pcrs->set(pcrs, pcr, pcr_after))
		{
			return status;
		}
	}
	else
	{
		pcr_after = pcrs->extend(pcrs, pcr, measurement);
		if (pcr_after.ptr)
		{
			return status;
		}
	}
	return FAILED;
}

METHOD(pts_component_t, finalize, bool,
	pts_ita_comp_ima_t *this, u_int8_t qualifier)
{
	u_int32_t vid, name;
	enum_name_t *names;
	bool success = TRUE;

	this->name->set_qualifier(this->name, qualifier);
	vid = this->name->get_vendor_id(this->name);
	name = this->name->get_name(this->name);
	names = pts_components->get_comp_func_names(pts_components, vid);

	if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
					  PTS_ITA_QUALIFIER_TYPE_TRUSTED))
	{
		/* finalize BIOS measurements */
		if (this->is_bios_registering)
		{
			/* close registration */
			this->is_bios_registering = FALSE;

			DBG1(DBG_PTS, "registered %d %N '%N' BIOS evidence measurements",
						   this->seq_no, pen_names, vid, names, name);
		}
		else if (this->seq_no < this->bios_count)
		{
			DBG1(DBG_PTS, "%d of %d %N '%N' BIOS evidence measurements missing",
						   this->bios_count - this->seq_no, this->bios_count,
						   pen_names, vid, names, name);
			success = FALSE;
		}
	}
	else if (qualifier == (PTS_ITA_QUALIFIER_FLAG_KERNEL |
						   PTS_ITA_QUALIFIER_TYPE_OS))
	{
		/* finalize IMA file measurements */
		if (this->is_ima_registering)
		{
			/* close registration */
			this->is_ima_registering = FALSE;

			DBG1(DBG_PTS, "registered %N '%N' boot aggregate evidence "
						  "measurement", pen_names, vid, names, name);
		}
		if (this->count)
		{
			DBG1(DBG_PTS, "processed %d %N '%N' file evidence measurements: "
						  "%d ok, %d unknown, %d differ, %d failed",
						   this->count, pen_names, vid, names, name,
						   this->count_ok, this->count_unknown,
						   this->count_differ, this->count_failed);
			success = !this->count_differ && !this->count_failed;
		}
	}
	else
	{
		DBG1(DBG_PTS, "unsupported functional component name qualifier");
		success = FALSE;
	}
	this->name->set_qualifier(this->name, PTS_QUALIFIER_UNKNOWN);

	return success;
}

METHOD(pts_component_t, get_ref, pts_component_t*,
	pts_ita_comp_ima_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(pts_component_t, destroy, void,
	pts_ita_comp_ima_t *this)
{
	int count;
	u_int32_t vid, name;
	enum_name_t *names;

	if (ref_put(&this->ref))
	{
		vid = this->name->get_vendor_id(this->name);
		name = this->name->get_name(this->name);
		names = pts_components->get_comp_func_names(pts_components, vid);

		if (this->is_bios_registering)
		{
			count = this->pts_db->delete_comp_measurements(this->pts_db,
													this->bios_cid, this->kid);
			DBG1(DBG_PTS, "deleted %d registered %N '%N' BIOS evidence "
						  "measurements", count, pen_names, vid, names, name);
		}
		if (this->is_ima_registering)
		{
			count = this->pts_db->delete_comp_measurements(this->pts_db,
													this->ima_cid, this->kid);
			DBG1(DBG_PTS, "deleted registered %N '%N' boot aggregate evidence "
						  "measurement", pen_names, vid, names, name);
		}
		this->bios_list->destroy_function(this->bios_list,
										 (void *)free_bios_entry);
		this->ima_list->destroy_function(this->ima_list,
										 (void *)free_ima_entry);
		this->name->destroy(this->name);
		free(this->keyid.ptr);
		free(this);
	}
}

/**
 * See header
 */
pts_component_t *pts_ita_comp_ima_create(u_int32_t depth,
										 pts_database_t *pts_db)
{
	pts_ita_comp_ima_t *this;

	INIT(this,
		.public = {
			.get_comp_func_name = _get_comp_func_name,
			.get_evidence_flags = _get_evidence_flags,
			.get_depth = _get_depth,
			.measure = _measure,
			.verify = _verify,
			.finalize = _finalize,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_IMA,
										  PTS_QUALIFIER_UNKNOWN),
		.depth = depth,
		.pts_db = pts_db,
		.bios_list = linked_list_create(),
		.ima_list = linked_list_create(),
		.pcr_info = lib->settings->get_bool(lib->settings,
						"%s.plugins.imc-attestation.pcr_info", TRUE, lib->ns),
		.ref = 1,
	);

	return &this->public;
}

