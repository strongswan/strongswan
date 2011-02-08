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
 * @defgroup tnc_imc_t tnc_imc
 * @{ @ingroup tnc_imc
 */

#ifndef TNC_IMC_H_
#define TNC_IMC_H_

#include <tnc/imc/imc.h>

/**
 * Create an Integrity Measurement Collector.
 *
 * @param name			name of the IMC
 * @param filename		path to the dynamic IMC library
 * @return				instance of the imc_t interface
 */
imc_t* tnc_imc_create(char *name, char *filename);

#endif /** TNC_IMC_H_ @}*/
