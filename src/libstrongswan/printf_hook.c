/**
 * @file printf_hook.c
 *
 * @brief Printf hook definitions and arginfo functions.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "printf_hook.h"

/**
 * arginfo handler in printf() pointer
 */
int arginfo_ptr(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 0)
	{
		argtypes[0] = PA_POINTER;
	}
	return 1;
}

/**
 * arginfo handler for two prt arguments
 */
int arginfo_ptr_ptr(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		argtypes[0] = PA_POINTER;
		argtypes[1] = PA_POINTER;
	}
	return 2;
}

/**
 * arginfo handler for one ptr, one int
 */
int arginfo_ptr_int(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		argtypes[0] = PA_POINTER;
		argtypes[1] = PA_INT;
	}
	return 2;
}

/**
 * arginfo handler for two int arguments
 */
int arginfo_int_int(const struct printf_info *info, size_t n, int *argtypes)
{
	if (n > 1)
	{
		argtypes[0] = PA_INT;
		argtypes[1] = PA_INT;
	}
	return 2;
}

/**
 * special arginfo handler respecting alt flag
 */
int arginfo_int_alt_int_int(const struct printf_info *info, size_t n, int *argtypes)
{
	if (info->alt)
	{
		if (n > 1)
		{
			argtypes[0] = PA_INT;
			argtypes[1] = PA_INT;
		}
		return 2;
	}
	
	if (n > 0)
	{
		argtypes[0] = PA_INT;
	}
	return 1;
}

/**
 * special arginfo handler respecting alt flag
 */
int arginfo_ptr_alt_ptr_int(const struct printf_info *info, size_t n, int *argtypes)
{
	if (info->alt)
	{
		if (n > 1)
		{
			argtypes[0] = PA_POINTER;
			argtypes[1] = PA_INT;
		}
		return 2;
	}
	
	if (n > 0)
	{
		argtypes[0] = PA_POINTER;
	}
	return 1;
}
