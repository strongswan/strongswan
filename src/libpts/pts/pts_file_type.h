/*
 * Copyright (C) 2011 Sansar Choinyambuu
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
 * @defgroup pts_file_type pts_file_type
 * @{ @ingroup pts
 */

#ifndef PTS_FILE_TYPE_H_
#define PTS_FILE_TYPE_H_

typedef enum pts_file_type_t pts_file_type_t;

/**
 * PTS File Type
 * see section 3.17.3 of PTS Protocol: Binding to TNC IF-M Specification
 */
enum pts_file_type_t {
	/** Ignore */
	PTS_FILE_OTHER =				0x0000,
	/** CRTM */
	PTS_FILE_FIFO =					0x0001,
	/** BIOS */
	PTS_FILE_CHAR_SPEC =			0x0002,
	/** Platform Extensions */
	PTS_FILE_DIRECTORY =			0x0004,
	/** Motherboard firmware */
	PTS_FILE_BLOCK_SPEC =			0x0006,
	/** Initial Program Loader */
	PTS_FILE_REGULAR =		 		0x0008,
	/** Option ROMs */
	PTS_FILE_SYM_LINK =			 	0x000A,
	/** Option ROMs */
	PTS_FILE_SOCKET =			 	0x000C,
};

#endif /** PTS_FILE_TYPE_H_ @}*/
