/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup path_i path
 * @{ @ingroup utils_i
 */

#ifndef PATH_H_
#define PATH_H_

/**
 * Directory separator character in paths on this platform
 */
#ifdef WIN32
# define DIRECTORY_SEPARATOR "\\"
#else
# define DIRECTORY_SEPARATOR "/"
#endif

/**
 * Checks if given character means directory semarator
 * basically cluld be just (c == DIRECTORY_SEPARATOR[0]),
 * but on Windows more also `/` is allowed
 *
 * @param c			character to be tested
 * @return			TRUE if it is directory separator
 */
bool path_is_dirsep(int c);

/**
 * Finds pointer to first directory separarator valid in given path
 *
 * Basically strrchr() or memrchr(), but allows more than one valid characters
 * to be used on platform (mainly Windows) as directory separators.
 *
 * @param path		pathname to search in
 * @param len		length of data in @a path, can be (-1) if
 * 					path is NULL-terminated
 * @return			pointer to first occurence of directory separator,
 * 					NULL if there is no such one.
 */
char *path_first_dirsep(const char *path, int len);

/**
 * Finds pointer to last directory separarator valid in given path
 *
 * Basically strrchr() or memrchr(), but allows more than one valid characters
 * to be used on platform (mainly Windows) as directory separators.
 *
 * @param path		pathname to search in
 * @param len		length of data in @a path, can be (-1) if
 * 					path is NULL-terminated
 * @return			pointer to first occurence of directory separator,
 * 					NULL if there is no such one.
 */
char *path_last_dirsep(const char *path, int len);

/**
 * Like dirname(3) returns the directory part of the given null-terminated
 * pathname, up to but not including the final '/' (or '.' if no '/' is found).
 * Trailing '/' are not counted as part of the pathname.
 *
 * The difference is that it does this in a thread-safe manner (i.e. it does not
 * use static buffers) and does not modify the original path.
 *
 * @param path		original pathname
 * @return			allocated directory component
 */
char *path_dirname(const char *path);

/**
 * Like basename(3) returns the filename part of the given null-terminated path,
 * i.e. the part following the final '/' (or '.' if path is empty or NULL).
 * Trailing '/' are not counted as part of the pathname.
 *
 * The difference is that it does this in a thread-safe manner (i.e. it does not
 * use static buffers) and does not modify the original path.
 *
 * @param path		original pathname
 * @return			allocated filename component
 */
char *path_basename(const char *path);

/**
 * Check if a given path is absolute.
 *
 * @param path		path to check
 * @return			TRUE if absolute, FALSE if relative
 */
bool path_absolute(const char *path);

/**
 * Creates a directory and all required parent directories.
 *
 * @param path		path to the new directory
 * @param mode		permissions of the new directory/directories
 * @return			TRUE on success
 */
bool mkdir_p(const char *path, mode_t mode);

#endif /** PATH_H_ @} */
