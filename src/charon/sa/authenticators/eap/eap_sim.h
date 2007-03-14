/**
 * @file eap_sim.h
 *
 * @brief Interface of eap_sim_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#ifndef EAP_SIM_H_
#define EAP_SIM_H_

typedef struct eap_sim_t eap_sim_t;
typedef enum sim_subtype_t sim_subtype_t;
typedef enum sim_attribute_t sim_attribute_t;

#include <sa/authenticators/eap/eap_method.h>

/**
 * Subtypes of SIM messages
 */
enum sim_subtype_t {
	SIM_START = 10,
	SIM_CHALLENGE = 11,
	SIM_NOTIFICATION = 12,
	SIM_CLIENT_ERROR = 14,
};

/**
 * enum names for sim_subtype_t
 */
extern enum_name_t *sim_subtype_names;

enum sim_attribute_t {
	/** defines the end of attribute list */
	AT_END = -1,
	AT_RAND = 1,
	AT_AUTN = 2,
	AT_RES = 3,
	AT_AUTS = 4,
	AT_PADDING = 6,
	AT_NONCE_MT = 7,
	AT_PERMANENT_ID_REQ = 10,
	AT_MAC = 11,
	AT_NOTIFICATION = 12,
	AT_ANY_ID_REQ = 13,
	AT_IDENTITY = 14,
	AT_VERSION_LIST = 15,
	AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17,
	AT_COUNTER = 19,
	AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21,
	AT_CLIENT_ERROR_CODE = 22,
	AT_IV = 129,
	AT_ENCR_DATA = 130,
	AT_NEXT_PSEUDONYM = 132,
	AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134,
	AT_RESULT_IND = 135,
};

/**
 * enum names for sim_subtype_t
 */
extern enum_name_t *sim_attribute_names;

/** 
 * @brief Cardreaders SIM function.
 *
 * @param rand			RAND to run algo with
 * @param rand_length	length of value in rand
 * @param sres			buffer to get SRES
 * @param sres_length	size of buffer in sres, returns bytes written to SRES
 * @param kc			buffer to get Kc
 * @param kc_length		size of buffer in Kc, returns bytes written to Kc
 * @return				zero on success
 */
typedef int (*sim_algo_t)(const unsigned char *rand, int rand_length,
						  unsigned char *sres, int *sres_length, 
						  unsigned char *kc, int *kc_length);

#ifndef SIM_READER_LIB
/** the library containing the cardreader with the SIM function */
#define SIM_READER_LIB "/root/strongswan-shared/trunk/src/charon/sa/authenticators/eap/sim_reader/sim_api.so"
#endif /* SIM_READER_LIB */

#ifndef SIM_READER_ALG
/** the SIM_READER_LIB's algorithm, uses sim_algo_t signature */
#define SIM_READER_ALG "sim_run_alg"
#endif /* SIM_READER_ALG */



/**
 * @brief Implementation of the eap_method_t interface using EAP-SIM.
 *
 * This EAP-SIM client implementation uses another pluggable library to
 * access the SIM card. This module is specified using the SIM_READER_LIB
 * definition. The function to run the algorithm has the sim_algo_t type and
 * is named as SIM_READER_ALG is defined.
 *
 * @b Constructors:
 *  - eap_sim_create()
 *  - eap_client_create() using eap_method EAP_SIM
 *
 * @ingroup eap
 */
struct eap_sim_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * @brief Creates the EAP method EAP-SIM.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_sim_t object
 *
 * @ingroup eap
 */
eap_sim_t *eap_create(eap_role_t role,
					  identification_t *server, identification_t *peer);

#endif /* EAP_SIM_H_ */
