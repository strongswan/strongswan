/*
 * Copyright (C) 2011 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup libpts libpts
 *
 * @defgroup libpts_plugins plugins
 * @ingroup libpts
 *
 * @defgroup swid swid
 * @ingroup libpts
 *
 * @addtogroup libpts
 * @{
 */

#ifndef LIBPTS_H_
#define LIBPTS_H_

#include "pts/components/pts_component_manager.h"

#include <library.h>

/**
 * Initialize libpts.
 *
 * @return			FALSE if initialization failed
 */
bool libpts_init(void);

/**
 * Deinitialize libpts.
 */
void libpts_deinit(void);

/**
 * PTS Functional Component manager
 */
extern pts_component_manager_t* pts_components;

#endif /** LIBPTS_H_ @}*/
