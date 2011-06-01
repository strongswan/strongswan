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
 * @defgroup libimcv libimcv
 *
 * @defgroup iplugins plugins
 * @ingroup libimcv
 *
 * @addtogroup libimcv
 * @{
 */

#ifndef IMCV_H_
#define IMCV_H_

#include <library.h>

/**
 * Initialize libimcv.
 *
 * @return				FALSE if initialization failed
 */
bool libimcv_init(void);

/**
 * Deinitialize libimcv.
 */
void libimcv_deinit(void);

#endif /** IMCV_H_ @}*/
