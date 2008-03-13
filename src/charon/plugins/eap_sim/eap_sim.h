/*
 * Copyright (C) 2007-2008 Martin Willi
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

/**
 * @defgroup eap_sim_i eap_sim
 * @{ @ingroup eap_sim
 */

#ifndef EAP_SIM_H_
#define EAP_SIM_H_

typedef struct eap_sim_t eap_sim_t;

#include <sa/authenticators/eap/eap_method.h>

/** the library containing with the triplet functions */
#ifndef SIM_READER_LIB
#error SIM_READER_LIB not specified, use --with-sim-reader option
#endif /* SIM_READER_LIB */

/** 
 * Cardreaders SIM function.
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

#ifndef SIM_READER_ALG
/** the SIM_READER_LIB's algorithm, uses sim_algo_t signature */
#define SIM_READER_ALG "sim_run_alg"
#endif /* SIM_READER_ALG */

/** 
 * Function to get a SIM triplet.
 *
 * @param identity		identity (imsi) to get a triplet for			
 * @param rand			buffer to get RAND
 * @param rand_length	size of buffer in rand, returns bytes written to RAND
 * @param sres			buffer to get SRES
 * @param sres_length	size of buffer in sres, returns bytes written to SRES
 * @param kc			buffer to get Kc
 * @param kc_length		size of buffer in Kc, returns bytes written to Kc
 * @return				zero on success
 */
typedef int (*sim_get_triplet_t)(char *identity,
								 unsigned char *rand, int *rand_length,
								 unsigned char *sres, int *sres_length, 
								 unsigned char *kc, int *kc_length);
						  
#ifndef SIM_READER_GET_TRIPLET
/** the SIM_READER_LIB's get-triplet function, uses sim_get_triplet_t signature */
#define SIM_READER_GET_TRIPLET "sim_get_triplet"
#endif /* SIM_READER_GET_TRIPLET */

/**
 * Implementation of the eap_method_t interface using EAP-SIM.
 *
 * This EAP-SIM client implementation uses another pluggable library to
 * access the SIM card/triplet provider. This module is specified using the
 * SIM_READER_LIB definition. It has to privde a sim_run_alg() function to
 * calculate a triplet (client), and/or a sim_get_triplet() function to get
 * a triplet (server). These functions are named to the SIM_READER_ALG and
 * the SIM_READER_GET_TRIPLET definitions.
 */
struct eap_sim_t {

	/**
	 * Implemented eap_method_t interface.
	 */
	eap_method_t eap_method_interface;
};

/**
 * Creates the EAP method EAP-SIM acting as server.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_sim_t object
 */
eap_sim_t *eap_sim_create_server(identification_t *server, identification_t *peer);

/**
 * Creates the EAP method EAP-SIM acting as peer.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			eap_sim_t object
 */
eap_sim_t *eap_sim_create_peer(identification_t *server, identification_t *peer);

#endif /* EAP_SIM_H_ @}*/
