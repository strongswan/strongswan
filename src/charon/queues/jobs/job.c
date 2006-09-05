/**
 * @file job.c
 * 
 * @brief Interface additions to job_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


#include "job.h"


mapping_t job_type_m[] = {
	{INCOMING_PACKET, "INCOMING_PACKET"},
	{RETRANSMIT_REQUEST, "RETRANSMIT_REQUEST"},
	{INITIATE, "INITIATE"},
	{ROUTE, "ROUTE"},
	{ACQUIRE, "ACQUIRE"},
	{DELETE_IKE_SA, "DELETE_IKE_SA"},
	{DELETE_CHILD_SA, "DELETE_CHILD_SA"},
	{REKEY_CHILD_SA, "REKEY_CHILD_SA"},
	{REKEY_IKE_SA, "REKEY_IKE_SA"},
	{SEND_KEEPALIVE, "SEND_KEEPALIVE"},
	{SEND_DPD, "SEND_DPD"},
	{MAPPING_END, NULL}
};
