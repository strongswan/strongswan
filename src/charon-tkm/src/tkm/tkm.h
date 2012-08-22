/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#ifndef TKM_H_
#define TKM_H_

#include "tkm_id_manager.h"
#include "tkm_chunk_map.h"

typedef struct tkm_t tkm_t;

/**
 * Trusted key manager context, contains tkm related globals.
 */
struct tkm_t {

	/**
	 * Context ID manager.
	 */
	tkm_id_manager_t *idmgr;

	/**
	 * Chunk-to-ID mappings.
	 */
	tkm_chunk_map_t *chunk_map;

};

/**
 * Initialize trusted key manager, creates "tkm" instance.
 *
 * @return				FALSE if initialization error occured
 */
bool tkm_init();

/**
 * Deinitialize trusted key manager, destroys "tkm" instance.
 */
void tkm_deinit();

/**
 * Trusted key manager instance, set after tkm_init() and before tkm_deinit()
 * calls.
 */
extern tkm_t *tkm;

#endif /** TKM_H_ */
