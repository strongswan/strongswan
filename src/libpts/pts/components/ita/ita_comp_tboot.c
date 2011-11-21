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
	 * Extended PCR last handled
	 */
	u_int32_t extended_pcr;

	/**
	 * Time of TBOOT measurement
	 */
	time_t measurement_time;

};

METHOD(pts_component_t, get_comp_func_name, pts_comp_func_name_t*,
	pts_ita_comp_tboot_t *this)
{
	return this->name;
}

METHOD(pts_component_t, get_evidence_flags, u_int8_t,
	pts_ita_comp_tboot_t *this)
{
	return PTS_REQ_FUNC_COMP_FLAG_PCR;
}

METHOD(pts_component_t, measure, status_t,
	pts_ita_comp_tboot_t *this, pts_t *pts, pts_comp_evidence_t **evidence)
{
	pts_comp_evidence_t *evid;
	char *meas_hex, *pcr_before_hex, *pcr_after_hex;
	chunk_t measurement, pcr_before, pcr_after;
	
	switch (this->extended_pcr)
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
			this->extended_pcr = PCR_TBOOT_POLICY;
			break;
		case PCR_TBOOT_POLICY:
			/* dummy data since currently the TBOOT log is not retrieved */
			meas_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_meas", NULL);
			pcr_before_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_before", NULL);
			pcr_after_hex = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.pcr18_after", NULL);
			this->extended_pcr = PCR_TBOOT_MLE;
			break;
		default:
			return FAILED;
	}

	measurement = chunk_from_hex(
					chunk_create(meas_hex, strlen(meas_hex)), NULL);
	pcr_before = chunk_from_hex(
					chunk_create(pcr_before_hex, strlen(pcr_before_hex)), NULL);
	pcr_after = chunk_from_hex(
					chunk_create(pcr_after_hex, strlen(pcr_after_hex)), NULL);

	evid = *evidence = pts_comp_evidence_create(this->name, 0,
							    this->extended_pcr,
								PTS_MEAS_ALGO_SHA1, PTS_PCR_TRANSFORM_NO,
								this->measurement_time, measurement);
	evid->set_pcr_info(evid, pcr_before, pcr_after);

	return (this->extended_pcr == PCR_TBOOT_MLE) ? SUCCESS : NEED_MORE;
}

METHOD(pts_component_t, verify, status_t,
	pts_ita_comp_tboot_t *this, pts_t *pts, pts_database_t *pts_db,
	pts_comp_evidence_t *evidence)
{
	bool has_pcr_info;
	u_int32_t extended_pcr;
	pts_meas_algorithms_t algo;
	pts_pcr_transform_t transform;
	time_t measurement_time;
	chunk_t measurement, pcr_before, pcr_after;
	pcr_entry_t *entry;

	switch (this->extended_pcr)
	{
		case 0:
			this->extended_pcr = PCR_TBOOT_POLICY;
			break;
		case PCR_TBOOT_POLICY:
			this->extended_pcr = PCR_TBOOT_MLE;
			break;
		default:
			return FAILED;
	}

	measurement = evidence->get_measurement(evidence, &extended_pcr,
								&algo, &transform, &measurement_time);
	if (extended_pcr != this->extended_pcr)
	{
		return FAILED;
	}

	/* TODO check measurement in database */

	has_pcr_info = evidence->get_pcr_info(evidence, &pcr_before, &pcr_after);
	if (has_pcr_info)
	{
		entry = malloc_thing(pcr_entry_t);
		entry->pcr_number = extended_pcr;
		memcpy(entry->pcr_value, pcr_after.ptr, PCR_LEN);
		pts->add_pcr_entry(pts, entry);
	}

	return (this->extended_pcr == PCR_TBOOT_MLE) ? SUCCESS : NEED_MORE;
}

METHOD(pts_component_t, destroy, void,
	pts_ita_comp_tboot_t *this)
{
	this->name->destroy(this->name);
	free(this);
}

/**
 * See header
 */
pts_component_t *pts_ita_comp_tboot_create(u_int8_t qualifier)
{
	pts_ita_comp_tboot_t *this;

	INIT(this,
		.public = {
			.get_comp_func_name = _get_comp_func_name,
			.get_evidence_flags = _get_evidence_flags,
			.measure = _measure,
			.verify = _verify,
			.destroy = _destroy,
		},
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_TBOOT,
										  qualifier),
	);

	return &this->public;
}

