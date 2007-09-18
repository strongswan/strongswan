/**
 * @file optionsfrom.h
 * 
 * @brief Read command line options from a file
 * 
 */

/*
 * Copyright (C) 1998, 1999  Henry Spencer.
 * Copyright (C) 2007 Andreas Steffen, Hochschule fuer Technik Rapperswil
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

#ifndef OPTIONSFROM_H_
#define OPTIONSFROM_H_

/**
 * @brief Pick up more options from a file, in the middle of an option scan
 * 
 * @param filename				file containing the options
 * @param argcp					pointer to argc
 * @param argvp					pointer to argv[]
 * @param optind				current optind, number of next argument
 * @param errfile				where to report errors (NULL means return)
 * @return						NULL if successful, error string otherwise
 */
err_t optionsfrom(const char *filename, int *argcp, char **argvp[], int optind, FILE *errfile);

#endif /*OPTIONSFROM_H_*/
