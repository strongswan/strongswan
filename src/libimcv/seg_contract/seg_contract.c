/*
 * Copyright (C) 2014 Andreas Steffen
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

#include "seg_contract.h"

#include <utils/debug.h>

#include <tncif_pa_subtypes.h>

typedef struct private_seg_contract_t private_seg_contract_t;

/**
 * Private data of a seg_contract_t object.
 *
 */
struct private_seg_contract_t {

	/**
	 * Public seg_contract_t interface.
	 */
	seg_contract_t public;

	/**
	 * PA-TNC message type
	 */
	pen_type_t msg_type;

	/**
	 * Maximum PA-TNC attribute size
	 */
	uint32_t max_attr_size;

	/**
	 * Maximum PA-TNC attribute segment size
	 */
	uint32_t max_seg_size;

	/**
	 * Is this a null contract?
	 */
	bool is_null;

	/**
	 * Contract role
	 */
	bool is_issuer;

	/**
	 * Issuer ID (either IMV ID or IMC ID)
	 */
	TNC_UInt32 issuer_id;

	/**
	 * IMC/IMV role
	 */
	bool is_imc;

};

METHOD(seg_contract_t, get_msg_type, pen_type_t,
	private_seg_contract_t *this)
{
	return this->msg_type;
}

METHOD(seg_contract_t, set_max_size, void,
	private_seg_contract_t *this, uint32_t max_attr_size, uint32_t max_seg_size)
{
	this->max_attr_size = max_attr_size;
	this->max_seg_size = max_seg_size;
	this->is_null = max_attr_size == SEG_CONTRACT_MAX_SIZE_VALUE &&
					max_seg_size  == SEG_CONTRACT_MAX_SIZE_VALUE;
}

METHOD(seg_contract_t, get_max_size, void,
	private_seg_contract_t *this, uint32_t *max_attr_size, uint32_t *max_seg_size)
{
	if (max_attr_size)
	{
		*max_attr_size = this->max_attr_size;
	}
	if (max_seg_size)
	{
		*max_seg_size = this->max_seg_size;
	}
}

METHOD(seg_contract_t, is_issuer, bool,
	private_seg_contract_t *this)
{
	return this->is_issuer;
}

METHOD(seg_contract_t, is_null, bool,
	private_seg_contract_t *this)
{
	return this->is_null;
}

METHOD(seg_contract_t, get_info_string, void,
	private_seg_contract_t *this, char *buf, size_t len, bool request)
{
	enum_name_t *pa_subtype_names;
	uint32_t msg_vid, msg_subtype;
	char *pos = buf;
	int written;

	/* nul-terminate the string buffer */
	buf[--len] = '\0';

	if (this->is_issuer && request)
	{
		written = snprintf(pos, len, "%s %d requests",
						  this->is_imc ? "IMC" : "IMV", this->issuer_id);
	}
	else
	{
		written = snprintf(pos, len, "received");
	}
	if (written < 0 || written > len)
	{
		return;
	}
	pos += written;
	len -= written;

	written = snprintf(pos, len, " a %ssegmentation contract%s ",
					   this->is_null ? "null" : "", request ? "" : " response");
	if (written < 0 || written > len)
	{
		return;
	}
	pos += written;
	len -= written;

	if (!this->is_issuer && this->issuer_id != TNC_IMVID_ANY)
	{
		written = snprintf(pos, len, "from %s %d ",
						   this->is_imc ? "IMV" : "IMC", this->issuer_id);
		if (written < 0 || written > len)
		{
			return;
		}
		pos += written;
		len -= written;
	}

	msg_vid     = this->msg_type.vendor_id;
	msg_subtype = this->msg_type.type;
	pa_subtype_names = get_pa_subtype_names(msg_vid);
	if (pa_subtype_names)
	{
		written = snprintf(pos, len, "for PA message type '%N/%N' "
						   "0x%06x/0x%08x", pen_names, msg_vid,
						   pa_subtype_names, msg_subtype, msg_vid,
						   msg_subtype);
	}
	else
	{
		written = snprintf(pos, len, "for PA message type '%N' "
						   "0x%06x/0x%08x", pen_names, msg_vid,
						   msg_vid, msg_subtype);
	}
	if (written < 0 || written > len)
	{
		return;
	}
	pos += written;
	len -= written;

	if (!this->is_null)
	{
		written = snprintf(pos, len, "\n  maximum attribute size of %u bytes "
						   "with ", this->max_attr_size);
		if (written < 0 || written > len)
		{
			return;
		}
		pos += written;
		len -= written;

		if (this->max_seg_size == SEG_CONTRACT_MAX_SIZE_VALUE)
		{
			written = snprintf(pos, len, "no segmentation");
		}
		else
		{
			written = snprintf(pos, len, "maximum segment size of %u bytes",
							   this->max_seg_size);
		}
	}
}

METHOD(seg_contract_t, destroy, void,
	private_seg_contract_t *this)
{
	free(this);
}

/**
 * See header
 */
seg_contract_t *seg_contract_create(pen_type_t msg_type,
								    uint32_t max_attr_size,
									uint32_t max_seg_size,
									bool is_issuer, TNC_UInt32 issuer_id,
									bool is_imc)
{
	private_seg_contract_t *this;

	INIT(this,
		.public = {
			.get_msg_type = _get_msg_type,
			.set_max_size = _set_max_size,
			.get_max_size = _get_max_size,
			.is_issuer = _is_issuer,
			.is_null = _is_null,
			.get_info_string = _get_info_string,
			.destroy = _destroy,
		},
		.msg_type = msg_type,
		.max_attr_size = max_attr_size,
		.max_seg_size = max_seg_size,
		.is_issuer = is_issuer,
		.issuer_id = issuer_id,
		.is_imc = is_imc,
		.is_null = max_attr_size == SEG_CONTRACT_MAX_SIZE_VALUE &&
				   max_seg_size  == SEG_CONTRACT_MAX_SIZE_VALUE,
	);

	return &this->public;
}

