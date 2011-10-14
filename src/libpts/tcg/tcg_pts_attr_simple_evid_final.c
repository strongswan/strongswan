/*
 * Copyright (C) 2011 Sansar Choinyambuu
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

#include "tcg_pts_attr_simple_evid_final.h"

#include <pa_tnc/pa_tnc_msg.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
#include <debug.h>

typedef struct private_tcg_pts_attr_simple_evid_final_t private_tcg_pts_attr_simple_evid_final_t;

/**
 * Simple Evidence Final
 * see section 3.15.2 of PTS Protocol: Binding to TNC IF-M Specification
 * 
 *					   1				   2				   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	 Flags		|	Reserved	| Optional Composite Hash Alg 	|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				Optional TPM PCR Composite Length				|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~		   Optional TPM PCR Composite (Variable Length)			~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |				Optional TPM Quote Signature Length				|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~		 Optional TPM Quote Signature (Variable Length)			~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~		 Optional Evidence Signature (Variable Length)			~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define PTS_SIMPLE_EVID_FINAL_SIZE			2
#define PTS_SIMPLE_EVID_FINAL_RESERVED		0x00

/**
 * Private data of an tcg_pts_attr_simple_evid_final_t object.
 */
struct private_tcg_pts_attr_simple_evid_final_t {

	/**
	 * Public members of tcg_pts_attr_simple_evid_final_t
	 */
	tcg_pts_attr_simple_evid_final_t public;

	/**
	 * Attribute vendor ID
	 */
	pen_t vendor_id;

	/**
	 * Attribute type
	 */
	u_int32_t type;

	/**
	 * Attribute value
	 */
	chunk_t value;
	
	/**
	 * Noskip flag
	 */
	bool noskip_flag;

	/**
	 * Is Evidence Signature included
	 */
	bool evid_sign_included;
	
	/**
	 * Set of flags for Simple Evidence Final
	 */
	pts_simple_evid_final_flag_t flags;

	/**
	 * Optional Composite Hash Algorithm
	 */
	pts_meas_algorithms_t comp_hash_algorithm;
	
	/**
	 * Optional TPM PCR Composite
	 */
	chunk_t pcr_comp;
	
	/**
	 * Optional TPM Quote Signature
	 */
	chunk_t tpm_quote_sign;
	
	/**
	 * Optional Evidence Signature
	 */
	chunk_t evid_sign;

};

METHOD(pa_tnc_attr_t, get_vendor_id, pen_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->vendor_id;
}

METHOD(pa_tnc_attr_t, get_type, u_int32_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->type;
}

METHOD(pa_tnc_attr_t, get_value, chunk_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->value;
}

METHOD(pa_tnc_attr_t, get_noskip_flag, bool,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->noskip_flag;
}

METHOD(pa_tnc_attr_t, set_noskip_flag,void,
	private_tcg_pts_attr_simple_evid_final_t *this, bool noskip)
{
	this->noskip_flag = noskip;
}

METHOD(pa_tnc_attr_t, build, void,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	bio_writer_t *writer;
	u_int8_t flags = 0;
	
	writer = bio_writer_create(PTS_SIMPLE_EVID_FINAL_SIZE);

	/* Determine the flags to set*/
	if (this->flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO)
	{
		flags += 64;
	}
	else if (this->flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2)
	{
		flags += 128;
	}
	else if (this->flags == PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2_CAP_VER)
	{
		flags += 192;
	}
	if (this->evid_sign_included)
	{
		flags += 32;
	}
	
	writer->write_uint8 (writer, flags);
	writer->write_uint8 (writer, PTS_SIMPLE_EVID_FINAL_RESERVED);
	
	/* Optional fields */
	if (this->comp_hash_algorithm)
	{
		writer->write_uint16(writer, this->comp_hash_algorithm);
	}
	if (this->pcr_comp.ptr && this->pcr_comp.len > 0)
	{
		writer->write_uint32 (writer, this->pcr_comp.len);
		writer->write_data (writer, this->pcr_comp);
	}
	if (this->tpm_quote_sign.ptr && this->tpm_quote_sign.len > 0)
	{
		writer->write_uint32 (writer, this->tpm_quote_sign.len);
		writer->write_data (writer, this->tpm_quote_sign);
	}
	if (this->evid_sign.ptr && this->evid_sign.len > 0)
	{
		writer->write_data (writer, this->evid_sign);
	}
	
	this->value = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);
}

METHOD(pa_tnc_attr_t, process, status_t,
	private_tcg_pts_attr_simple_evid_final_t *this, u_int32_t *offset)
{
	bio_reader_t *reader;
	u_int8_t flags;
	u_int8_t reserved;
	//u_int16_t algorithm;
	
	if (this->value.len < PTS_SIMPLE_EVID_FINAL_SIZE)
	{
		DBG1(DBG_TNC, "insufficient data for Simple Evidence Final");
		*offset = 0;
		return FAILED;
	}
	reader = bio_reader_create(this->value);
	
	reader->read_uint8(reader, &flags);
	
	/* Determine the flags to set*/
	if (!((flags >> 7) & 1) && !((flags >> 6) & 1))
	{
		this->flags = PTS_SIMPLE_EVID_FINAL_FLAG_NO;
	}
	else if (!((flags >> 7) & 1) && ((flags >> 6) & 1))
	{
		this->flags = PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO;
	}
	else if (((flags >> 7) & 1) && !((flags >> 6) & 1))
	{
		this->flags = PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2;
	}
	else if (((flags >> 7) & 1) && ((flags >> 6) & 1))
	{
		this->flags = PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO2_CAP_VER;
	}
	if ((flags >> 5) & 1)
	{
		this->evid_sign_included = TRUE;
	}
	
	reader->read_uint8(reader, &reserved);
	
	/*  Optional Composite Hash Algorithm and TPM PCR Composite field is included */
	if (this->flags != PTS_SIMPLE_EVID_FINAL_FLAG_NO)
	{
		u_int32_t pcr_comp_len;
		u_int32_t tpm_quote_sign_len;
		
		/** TODO: Ignoring Hashing algorithm field
		 * There is no flag defined which indicates the precense of it
		 * reader->read_uint16(reader, &algorithm);
		 * this->comp_hash_algorithm = algorithm;
		 */
		reader->read_uint32(reader, &pcr_comp_len);
		reader->read_data(reader, pcr_comp_len, &this->pcr_comp);
		this->pcr_comp = chunk_clone(this->pcr_comp);
		reader->read_uint32(reader, &tpm_quote_sign_len);
		reader->read_data(reader, tpm_quote_sign_len, &this->tpm_quote_sign);
		this->tpm_quote_sign = chunk_clone(this->tpm_quote_sign);
	}
	
	/*  Optional Evidence Signature field is included */
	if (this->evid_sign_included)
	{
		u_int32_t evid_sign_len = reader->remaining(reader);
		reader->read_data(reader, evid_sign_len, &this->evid_sign);
		this->evid_sign = chunk_clone(this->evid_sign);
	}
	
	reader->destroy(reader);
	return SUCCESS;
}

METHOD(pa_tnc_attr_t, destroy, void,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	free(this->value.ptr);
	free(this->pcr_comp.ptr);
	free(this->tpm_quote_sign.ptr);
	free(this->evid_sign.ptr);
	free(this);
}

METHOD(tcg_pts_attr_simple_evid_final_t, is_evid_sign_included, bool,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->evid_sign_included;
}

METHOD(tcg_pts_attr_simple_evid_final_t, get_flags, pts_simple_evid_final_flag_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->flags;
}

METHOD(tcg_pts_attr_simple_evid_final_t, get_comp_hash_algorithm, pts_meas_algorithms_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->comp_hash_algorithm;
}

METHOD(tcg_pts_attr_simple_evid_final_t, get_pcr_comp, chunk_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->pcr_comp;
}

METHOD(tcg_pts_attr_simple_evid_final_t, get_tpm_quote_sign, chunk_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->tpm_quote_sign;
}

METHOD(tcg_pts_attr_simple_evid_final_t, get_evid_sign, chunk_t,
	private_tcg_pts_attr_simple_evid_final_t *this)
{
	return this->evid_sign;
}

/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_simple_evid_final_create(
					   bool evid_sign_included,
					   pts_simple_evid_final_flag_t flags,
					   pts_meas_algorithms_t comp_hash_algorithm,
					   chunk_t pcr_comp,
					   chunk_t tpm_quote_sign,
					   chunk_t evid_sign)
{
	private_tcg_pts_attr_simple_evid_final_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_vendor_id = _get_vendor_id,
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.is_evid_sign_included = _is_evid_sign_included,
			.get_flags = _get_flags,
			.get_comp_hash_algorithm = _get_comp_hash_algorithm,
			.get_pcr_comp = _get_pcr_comp,
			.get_tpm_quote_sign = _get_tpm_quote_sign,
			.get_evid_sign = _get_evid_sign,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_SIMPLE_EVID_FINAL,
		.evid_sign_included = evid_sign_included,
		.flags = flags,
		.comp_hash_algorithm = comp_hash_algorithm,
		.pcr_comp = chunk_clone(pcr_comp),
		.tpm_quote_sign = chunk_clone(tpm_quote_sign),
		.evid_sign = chunk_clone(evid_sign),
	);

	return &this->public.pa_tnc_attribute;
}


/**
 * Described in header.
 */
pa_tnc_attr_t *tcg_pts_attr_simple_evid_final_create_from_data(chunk_t data)
{
	private_tcg_pts_attr_simple_evid_final_t *this;

	INIT(this,
		.public = {
			.pa_tnc_attribute = {
				.get_vendor_id = _get_vendor_id,
				.get_type = _get_type,
				.get_value = _get_value,
				.get_noskip_flag = _get_noskip_flag,
				.set_noskip_flag = _set_noskip_flag,
				.build = _build,
				.process = _process,
				.destroy = _destroy,
			},
			.is_evid_sign_included = _is_evid_sign_included,
			.get_flags= _get_flags,
			.get_comp_hash_algorithm = _get_comp_hash_algorithm,
			.get_pcr_comp = _get_pcr_comp,
			.get_tpm_quote_sign = _get_tpm_quote_sign,
			.get_evid_sign = _get_evid_sign,
		},
		.vendor_id = PEN_TCG,
		.type = TCG_PTS_SIMPLE_EVID_FINAL,
		.value = chunk_clone(data),
	);

	return &this->public.pa_tnc_attribute;
}
