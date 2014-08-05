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

/**
 * @defgroup seg_contract seg_contract
 * @{ @ingroup libimcv
 */

#ifndef SEG_CONTRACT_H_
#define SEG_CONTRACT_H_

typedef struct seg_contract_t seg_contract_t;

#include <library.h>
#include <pen/pen.h>

#include <tncif.h>

#define SEG_CONTRACT_MAX_SIZE_VALUE		0xffffffff
#define SEG_CONTRACT_NO_FRAGMENTATION	SEG_CONTRACT_MAX_SIZE_VALUE

/**
 * Interface for a PA-TNC attribute segmentation contract
 *
 */
struct seg_contract_t {

	/**
	 * Get the PA-TNC message type.
	 *
	 * @return					PA-TNC Message type
	 */
	pen_type_t (*get_msg_type)(seg_contract_t *this);

	/**
	 * Set maximum PA-TNC attribute and segment size in octets
	 *
	 * @param max_attr_size		Maximum PA-TNC attribute size in octets
	 * @param max_seg_size		Maximum PA-TNC attribute segment size in octets
	 */
	void (*set_max_size)(seg_contract_t *this, uint32_t max_attr_size,
											   uint32_t max_seg_size);

	/**
	 * Get maximum PA-TNC attribute and segment size in octets
	 *
	 * @param max_attr_size		Maximum PA-TNC attribute size in octets
	 * @param max_seg_size		Maximum PA-TNC attribute segment size in octets
	 */
	void (*get_max_size)(seg_contract_t *this, uint32_t *max_attr_size,
											   uint32_t *max_seg_size);

	/**
	 * Get contract role
	 *
	 * @return					TRUE:  contracting party (issuer),
	 *							FALSE: contracted party 
	 */
	bool (*is_issuer)(seg_contract_t *this);

	/**
	 * Is this a null contract ?
	 *
	 * @return					TRUE if null contract
	 */
	bool (*is_null)(seg_contract_t *this);

	/**
	 * Get an info string about the contract
	 *
	 * @param buf				String buffer of at least size len
	 * @param len				Size of string buffer
	 */
	void (*get_info_string)(seg_contract_t *this, char *buf, size_t len);

	/**
	 * Destroys a seg_contract_t object.
	 */
	void (*destroy)(seg_contract_t *this);
};

/**
 * Create a PA-TNC attribute segmentation contract 
 *
 * @param msg_type				PA-TNC message type
 * @param max_attr_size		Maximum PA-TNC attribute size in octets
 * @param max_seg_size		Maximum PA-TNC attribute segment size in octets
 * @param is_issuer			TRUE if issuer of the contract
 * @param issuer_id			IMC or IMV ID of issuer
 * @param is_imc			TRUE if IMC, FALSE if IMV
 */
seg_contract_t* seg_contract_create(pen_type_t msg_type,
									uint32_t max_attr_size,
									uint32_t max_seg_size,
									bool is_issuer, TNC_UInt32 issuer_id,
									bool is_imc);

#endif /** SEG_CONTRACT_H_ @}*/
