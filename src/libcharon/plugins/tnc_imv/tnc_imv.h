/*
 * Copyright (C) 2010 Andreas Steffen
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
 *
 * @defgroup tnc_imv_t tnc_imv
 * @{ @ingroup tnc_imv
 */

#ifndef TNC_IMV_H_
#define TNC_IMV_H_

#include <tnc/imv/imv.h>

/**
 * Create an Integrity Measurement Verifier.
 *
 * @param name			name of the IMV
 * @param filename		path to the dynamic IMV library
 * @return				instance of the imv_t interface
 */
imv_t* tnc_imv_create(char *name, char *filename);

#endif /** TNC_IMV_H_ @}*/
