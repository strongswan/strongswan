/*
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Copyright (C) 2012 Tobias Brunner
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
 * @defgroup libipsec libipsec
 *
 * @addtogroup libipsec
 * @{
 */

#ifndef IPSEC_H_
#define IPSEC_H_

#include "ipsec_sa_mgr.h"

#include <library.h>

typedef struct ipsec_t ipsec_t;

/**
 * User space IPsec implementation.
 */
struct ipsec_t {

	/**
	 * IPsec SA manager instance
	 */
	ipsec_sa_mgr_t *sas;

};

/**
 * The single instance of ipsec_t.
 *
 * Set between calls to libipsec_init() and libipsec_deinit() calls.
 */
extern ipsec_t *ipsec;

/**
 * Initialize libipsec.
 *
 * @return				FALSE if integrity check failed
 */
bool libipsec_init();

/**
 * Deinitialize libipsec.
 */
void libipsec_deinit();

#endif /** IPSEC_H_ @}*/
