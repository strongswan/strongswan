/*
 * libipsecpolicy version information
 * Copyright (C) 2003   Michael Richardson <mcr@freeswan.org>
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: version.in.c,v 1.1 2004/03/15 20:35:25 as Exp $
 */

#define	V	"xxx"		/* substituted in by Makefile */
static const char ipsecpolicy_number[] = V;
static const char ipsecpolicy_string[] = "Linux FreeS/WAN policylib " V;

/*
 - ipsec_version_code - return IPsec version number/code, as string
 */
const char *
ipsec_version_code(void)
{
	return ipsecpolicy_number;
}

/*
 - ipsec_version_string - return full version string
 */
const char *
ipsec_version_string(void)
{
	return ipsecpolicy_string;
}
