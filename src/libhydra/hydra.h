/*
 * Copyright (C) 2010 Tobias Brunner
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
 * @defgroup libhydra libhydra
 *
 */

/**
 * @defgroup hydra hydra
 * @{ @ingroup libhydra
 */

#ifndef HYDRA_H_
#define HYDRA_H_

#include <library.h>

/**
 * Initialize libhydra.
 * @return				FALSE if integrity check failed
 */
bool libhydra_init();

/**
 * Deinitialize libhydra.
 */
void libhydra_deinit();

#endif /** HYDRA_H_ @}*/
