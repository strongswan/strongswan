/*
 * Copyright (C) 2020 Noel Kuntze for Contauro AG
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
 * @defgroup vici_prompt vici_prompt
 * @{ @ingroup vici
 */

#ifndef VICI_PROMPT_H_
#define VICI_PROMPT_H_

#include "vici_dispatcher.h"

typedef struct vici_prompt_t vici_prompt_t;

/**
 * prompt manager for VICI clients that want to provide credentials when they are requested by a function
 */
struct vici_prompt_t {
	void (*destroy)(vici_prompt_t *this);
};

/**
 * Create a vici_prompt instance.
 *
 * @param dispatcher		dispatcher to receive requests from
 * @return					prompt backend
 */
vici_prompt_t *vici_prompt_create(vici_dispatcher_t *dispatcher);

#endif /** VICI_PROMPT_H_ @}*/
