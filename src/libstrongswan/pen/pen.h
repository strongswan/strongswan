/*
 * Copyright (C) 2011 Andreas Steffen
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
 * @defgroup pen pen
 * @ingroup libstrongswan
 *
 * @defgroup pent pen
 * @{ @ingroup pen
 */

#ifndef PEN_H_
#define PEN_H_

#include <library.h>

typedef enum pen_t pen_t;

enum pen_t {
	PEN_IETF =		0x000000,	/*        0 */
	PEN_MICROSOFT = 0x000137,	/*      311 */
	PEN_OSC =		0x002358,	/*     9048 */
	PEN_TCG =		0x005597,	/*    21911 */
	PEN_FHH =		0x0080ab,	/*    32939 */
	PEN_ITA =		0x00902a,	/*    36906 */
	PEN_RESERVED =	0xffffff,	/* 16777215 */
};

/**
 * enum names for pen_t.
 */
extern enum_name_t *pen_names;

#endif /** PEN_H_ @}*/
