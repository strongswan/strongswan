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
 * @defgroup pts_funct_comp_name pts_funct_comp_name
 * @{ @ingroup pts
 */

#ifndef PTS_FUNCT_COMP_NAME_H_
#define PTS_FUNCT_COMP_NAME_H_

typedef enum pts_funct_comp_type_t pts_funct_comp_type_t;
typedef enum pts_funct_comp_name_t pts_funct_comp_name_t;
typedef struct pts_qualifier_t pts_qualifier_t;

/**
 * PTS Component Functional Type for Qualifier field
 */
enum pts_funct_comp_type_t {
	/** Unknown */
	PTS_FUNC_COMP_TYPE_UNKNOWN =			0x0,
	/** Trusted Platform */
	PTS_FUNC_COMP_TYPE_TRUSTED =			 0x1,
	/** Operating System */
	PTS_FUNC_COMP_TYPE_OS =				 0x2,
	/** Graphical User Interface */
	PTS_FUNC_COMP_TYPE_GUI =				 0x3,
	/** Application */
	PTS_FUNC_COMP_TYPE_APP =				0x4,
	/** Networking */
	PTS_FUNC_COMP_TYPE_NET =				 0x5,
	/** Library */
	PTS_FUNC_COMP_TYPE_LIB =				 0x6,
	/** TNC Defined Component */
	PTS_FUNC_COMP_TYPE_TNC =				 0x7,
	/** All matching Components */
	PTS_FUNC_COMP_TYPE_ALL =				 0xF,
};

/**
 * PTS Component Functional Name Binary Enumeration
 */
enum pts_funct_comp_name_t {
	/** Ignore */
	PTS_FUNC_COMP_NAME_IGNORE =				0x0000,
	/** CRTM */
	PTS_FUNC_COMP_NAME_CRTM =				 0x0001,
	/** BIOS */
	PTS_FUNC_COMP_NAME_BIOS =				 0x0002,
	/** Platform Extensions */
	PTS_FUNC_COMP_NAME_PLATFORM_EXT =		0x0003,
	/** Motherboard firmware */
	PTS_FUNC_COMP_NAME_BOARD =				0x0004,
	/** Initial Program Loader */
	PTS_FUNC_COMP_NAME_INIT_LOADER =		 0x0005,
	/** Option ROMs */
	PTS_FUNC_COMP_NAME_OPT_ROMS =			 0x0006,
};

/**
 * Qualifier for Functional Component
 */
struct pts_qualifier_t {
	bool	  kernel;
	bool	  sub_component;
	pts_funct_comp_type_t  type;
};

#endif /** PTS_FUNCT_COMP_NAME_H_ @}*/
