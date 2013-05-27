/*
 * Copyright (C) 2013 Andreas Steffen
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
 * @defgroup imv_os_batch_ending_t imv_os_batch_ending
 * @{ @ingroup imv_os
 */

#ifndef IMV_OS_BATCH_ENDING_H_
#define IMV_OS_BATCH_ENDING_H_

#include <tncif.h>

#include <imv/imv_agent.h>

/**
 * Implement the TNC_IMV_BatchEnding() function of the OS IMV
 *
 * @param imv_os			IMV agent
 * @param state				connection state
 * @param imv_id			IMV ID
 * @param msg_type			PA-TNC message subtype
 * @return					Result code
 */
TNC_Result imv_os_batch_ending(imv_agent_t *imv_os, imv_state_t *state,
							   TNC_IMVID imv_id, pen_type_t msg_type);

#endif /** IMV_OS_BATCH_ENDING_H_ @}*/
