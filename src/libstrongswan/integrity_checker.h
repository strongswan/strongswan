/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup integrity_checker integrity_checker
 * @{ @ingroup libstrongswan
 */

#ifndef INTEGRITY_CHECKER_H_
#define INTEGRITY_CHECKER_H_

#include <utils.h>
#include <plugins/plugin.h>

typedef struct integrity_checker_t integrity_checker_t;
typedef struct integrity_checksum_t integrity_checksum_t;

/**
 * Struct to hold a precalculated checksum, implemented in the checksum library.
 */
struct integrity_checksum_t {
	/* name of the checksum */
	char *name;
	/* checksum of the file on disk */
	u_int32_t file;
	/* checksum of the executable segment in memory */
	u_int32_t segment;
};

/**
 * Code integrity checker to detect non-malicious file manipulation.
 *
 * The integrity checker reads the checksums from a separate library
 * libchecksum.so to compare the checksums.
 */
struct integrity_checker_t {

	/**
	 * Check the integrity of a file on disk.
	 *
	 * @param name		name to lookup checksum
	 * @param file		path to file
	 * @return			TRUE if integrity tested successfully
	 */
	bool (*check_file)(integrity_checker_t *this, char *name, char *file);
	
	/**
	 * Build the integrity checksum of a file on disk.
	 *
	 * @param file		path to file
	 * @return			checksum, 0 on error
	 */
	u_int32_t (*build_file)(integrity_checker_t *this, char *file);
	
	/**
	 * Check the integrity of the code segment in memory.
	 *
	 * @param name		name to lookup checksum
	 * @param sym		a symbol in the segment to check
	 * @return			TRUE if integrity tested successfully
	 */
	bool (*check_segment)(integrity_checker_t *this, char *name, void *sym);
	
	/**
	 * Build the integrity checksum of a code segment in memory.
	 *
	 * @param sym		a symbol in the segment to check
	 * @return			checksum, 0 on error
	 */
	u_int32_t (*build_segment)(integrity_checker_t *this, void *sym);
	
	/**
	 * Destroy a integrity_checker_t.
	 */
	void (*destroy)(integrity_checker_t *this);
};

/**
 * Create a integrity_checker instance.
 */
integrity_checker_t *integrity_checker_create();

#endif /* INTEGRITY_CHECKER_H_ @}*/
