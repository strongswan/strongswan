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

};

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
	char *meas_hex, *pcr_before_hex, *pcr_after_hex;
	chunk_t measurement, pcr_before, pcr_after;
	size_t hash_size, pcr_len;
	u_int32_t extended_pcr;
	pts_pcr_transform_t pcr_transform;
	pts_meas_algorithms_t hash_algo;
	
	switch (this->seq_no++)
	{
		case 0:
			/* dummy data since currently the TBOOT log is not retrieved */
			time(&this->measurement_time);
			meas_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr17_meas", NULL);
			pcr_before_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr17_before", NULL);
			pcr_after_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr17_after", NULL);
			extended_pcr = PCR_TBOOT_POLICY;
			break;
		case 1:
			/* dummy data since currently the TBOOT log is not retrieved */
			meas_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_meas", NULL);
			pcr_before_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_before", NULL);
			pcr_after_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_after", NULL);
			extended_pcr = PCR_TBOOT_MLE;
			break;
		default:
			return FAILED;
	}

	if (meas_hex == NULL || pcr_before_hex == NULL || pcr_after_hex == NULL)
	{
		return FAILED;
	}

	hash_algo = pts->get_meas_algorithm(pts);
	hash_size = pts_meas_algo_hash_size(hash_algo);
	pcr_len = pts->get_pcr_len(pts);
	pcr_transform = pts_meas_algo_to_pcr_transform(hash_algo, pcr_len);

	/* get and check the measurement data */
	measurement = chunk_from_hex(
					chunk_create(meas_hex, strlen(meas_hex)), NULL);
	pcr_before = chunk_from_hex(
					chunk_create(pcr_before_hex, strlen(pcr_before_hex)), NULL);
	pcr_after = chunk_from_hex(
					chunk_create(pcr_after_hex, strlen(pcr_after_hex)), NULL);
	if (pcr_before.len != pcr_len || pcr_after.len != pcr_len ||
		measurement.len != hash_size)
	{
		DBG1(DBG_PTS, "TBOOT measurement or pcr data have the wrong size");
		free(measurement.ptr);
		free(pcr_before.ptr);
		free(pcr_after.ptr);
		return FAILED;
	}

	evid = *evidence = pts_comp_evidence_create(this->name->clone(this->name),
								this->depth, extended_pcr,
								hash_algo, pcr_transform,
								this->measurement_time, measurement);
	evid->set_pcr_info(evid, pcr_before, pcr_after);

	return (this->seq_no < 2) ? NEED_MORE : SUCCESS;
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
	);

	return &this->public;
}

