/**
 * @file state.c
 * 
 * @brief Interface for a specific IKE_SA state
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
#include "state.h"


/**
 * string mappings for ike_sa_state 
 */
mapping_t ike_sa_state_m[] = {
	{INITIATOR_INIT, "INITIATOR_INIT"},
	{RESPONDER_INIT, "RESPONDER_INIT"},
	{IKE_SA_INIT_REQUESTED, "IKE_SA_INIT_REQUESTED"},
	{IKE_SA_INIT_RESPONDED, "IKE_SA_INIT_RESPONDED"},
	{IKE_AUTH_REQUESTED, "IKE_AUTH_REQUESTED"},
	{IKE_SA_ESTABLISHED, "IKE_SA_ESTABLISHED"},
	{MAPPING_END, NULL}
};
