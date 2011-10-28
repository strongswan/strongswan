/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2009-2010 Andreas Steffen
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

#include <stdio.h>

/**
 * print attest usage info
 */
void usage(void)
{
	printf("\
Usage:\n\
  ipsec attest --files|--products [options]\n\
  \n\
  ipsec attest --files [--product <name>|--pid <id>]\n\
    Show a list of supported files with a sofware product name or\n\
    its primary key as a selector.\n\
  \n\
  ipsec attest --products [--file <path>|--fid <id>]\n\
    Show a list of software products with a file path or\n\
    its primary key as a selector.\n\
   \n");
}

