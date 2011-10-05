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

/**
 * @defgroup pts pts
 * @{ @ingroup pts
 */

#ifndef PTS_H_
#define PTS_H_

typedef struct pts_t pts_t;

#include "pts_error.h"
#include "pts_proto_caps.h"
#include "pts_meas_algo.h"
#include "pts_file_meas.h"
#include "pts_file_meta.h"
#include "pts_dh_group.h"

#include <library.h>

/**
 * UTF-8 encoding of the character used to delimiter the filename
 */
#define SOLIDUS_UTF				0x2F
#define REVERSE_SOLIDUS_UTF		0x5C

/**
 * Lenght of the generated nonce used for calculation of shared secret
 */
#define NONCE_LEN				20

/**
 * Class implementing the TCG Platform Trust System (PTS)
 *
 */
struct pts_t {

	/**
	 * Get PTS Protocol Capabilities
	 *
	 * @return				protocol capabilities flags
	 */
	pts_proto_caps_flag_t (*get_proto_caps)(pts_t *this);

	/**
	 * Set PTS Protocol Capabilities
	 *
	 * @param flags			protocol capabilities flags
	 */
	void (*set_proto_caps)(pts_t *this, pts_proto_caps_flag_t flags);

	/**
	 * Get PTS Measurement Algorithm
	 *
	 * @return				measurement algorithm
	 */
	pts_meas_algorithms_t (*get_meas_algorithm)(pts_t *this);

	/**
	 * Set PTS Measurement Algorithm
	 *
	 * @param algorithm		measurement algorithm
	 */
	void (*set_meas_algorithm)(pts_t *this, pts_meas_algorithms_t algorithm);

	/**
	 * Get PTS Diffie Hellman Group
	 *
	 * @return				DH Group
	 */
	pts_dh_group_t (*get_dh_group)(pts_t *this);

	/**
	 * Set PTS Diffie Hellman Group
	 *
	 * @param dh_group		DH Group
	 */
	void (*set_dh_group)(pts_t *this, pts_dh_group_t dh_group);

	/**
	 * Set PTS Diffie Hellman Object
	 *
	 * @param dh			D-H object
	 */
	bool (*create_dh)(pts_t *this, pts_dh_group_t group);

	/**
	 * Gets Own Diffie Hellman Public Value
	 *
	 * @param info			chunk to keep own public value
	 */
	void (*get_my_pub_val)(pts_t *this, chunk_t *pub_value);

	/**
	 * Sets the public value of partner.
	 *
	 * @param value		public value of partner
	 */
	void (*set_other_pub_val) (pts_t *this, chunk_t value);

	/**
	 * Calculates secret assessment value to be used for TPM Quote as an external data
	 *
	 * @param initiator_nonce		Initiator nonce (IMV nonce)
	 * @param responder_nonce		Responder nonce (IMC nonce)
	 * @param algorithm				Hashing algorithm
	 * @return						TRUE, FALSE if not both DH public values and
	 *															 nonces are set
	 */
	bool (*calculate_secret) (pts_t *this, chunk_t initiator_nonce,
						chunk_t responder_nonce, pts_meas_algorithms_t algorithm);

	/**
	 * Returns secret assessment value to be used for TPM Quote as an external data
	 *
	 * @return			Secret assessment value
	 */
	chunk_t (*get_secret) (pts_t *this);

	/**
	 * Get Platform and OS Info
	 *
	 * @return				platform and OS info
	 */
	char* (*get_platform_info)(pts_t *this);

	/**
	 * Set Platform and OS Info
	 *
	 * @param info			platform and OS info
	 */
	void (*set_platform_info)(pts_t *this, char *info);

	/**
	 * Get TPM 1.2 Version Info
	 *
	 * @param info			chunk containing a TPM_CAP_VERSION_INFO struct
	 * @return				TRUE if TPM Version Info available
	 */
	bool (*get_tpm_version_info)(pts_t *this, chunk_t *info);

	/**
	 * Set TPM 1.2 Version Info
	 *
	 * @param info			chunk containing a TPM_CAP_VERSION_INFO struct
	 */
	void (*set_tpm_version_info)(pts_t *this, chunk_t info);

	/**
	 * Get Attestation Identity Certificate or Public Key
	 *
	 * @return				AIK Certificate or Public Key
	 */
	certificate_t* (*get_aik)(pts_t *this);

	/**
	 * Set Attestation Identity Certificate or Public Key
	 *
	 * @param aik			AIK Certificate or Public Key
	 */
	void (*set_aik)(pts_t *this, certificate_t *aik);

	/**
	 * Check whether path is valid file/directory on filesystem
	 *
	 * @param path			Absolute path
	 * @param error_code	Output variable for PTS error code
	 * @return				TRUE if path is valid or file/directory doesn't exist
	 * 							or path is invalid
	 * 						FALSE if local error occurred within stat function
	 */
	bool (*is_path_valid)(pts_t *this, char *path, pts_error_code_t *error_code);

	/**
	* Compute a hash over a file
	 * @param hasher		Hasher to be used
	 * @param pathname		Absolute path of a file
	 * @param hash			Buffer to keep hash output
	 * @return				TRUE if path is valid and hashing succeeded, FALSE otherwise
	 */
	bool (*hash_file)(pts_t *this, hasher_t *hasher, char *pathname, u_char *hash);

	/**
	 * Do PTS File Measurements
	 *
	 * @param request_id	ID of PTS File Measurement Request
	 * @param pathname		Absolute pathname of file to be measured
	 * @param is_directory	if TRUE directory contents are measured
	 * @return				PTS File Measurements of NULL if FAILED
	 */
	pts_file_meas_t* (*do_measurements)(pts_t *this, u_int16_t request_id,
										char *pathname, bool is_directory);

	/**
	 * Obtain file metadata
	 *
	 * @param pathname		Absolute pathname of file/directory
	 * @param is_directory	if TRUE directory contents are requested
	 * @return				PTS File Metadata or NULL if FAILED
	 */
	pts_file_meta_t* (*get_metadata)(pts_t *this, char *pathname, bool is_directory);

	/**
	 * Reads given PCR value and returns it
	 *
	 * @param pcr_num		Number of PCR to read
	 * @param pcr_value		Chunk to save pcr read output
	 * @return				NULL in case of TSS error, PCR value otherwise
	 */
	bool (*read_pcr)(pts_t *this, u_int32_t pcr_num, chunk_t *pcr_value);

	/**
	 * Extends given PCR with given value
	 *
	 * @param pcr_num		Number of PCR to extend
	 * @param input			Value to extend
	 * @param output		Chunk to save PCR value after extension
	 * @return				FALSE in case of TSS error, TRUE otherwise
	 */
	bool (*extend_pcr)(pts_t *this, u_int32_t pcr_num, chunk_t input, chunk_t *output);

	/**
	 * Quote over PCR's
	 *
	 * @param pcrs			Set of PCR's to make quotation over
	 * @param quote			Chunk to save quote operation output
	 * @return				FALSE in case of TSS error, TRUE otherwise
	 */
	 bool (*quote_tpm)(pts_t *this, u_int32_t pcrs, chunk_t *quote);

	/**
	 * Destroys a pts_t object.
	 */
	void (*destroy)(pts_t *this);

};

/**
 * Creates an pts_t object
 *
 * @param is_imc			TRUE if running on an IMC
 */
pts_t* pts_create(bool is_imc);

#endif /** PTS_H_ @}*/