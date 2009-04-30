/*
 * minor network-address manipulation utilities
 * Copyright (C) 1998, 1999  Henry Spencer.
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
 */
#include "internal.h"
#include "freeswan.h"

/*
 - subnetof - given address and mask, return subnet part
 */
struct in_addr
subnetof(addr, mask)
struct in_addr addr;
struct in_addr mask;
{
	struct in_addr result;

	result.s_addr = addr.s_addr & mask.s_addr;
	return result;
}

/*
 - hostof - given address and mask, return host part
 */
struct in_addr
hostof(addr, mask)
struct in_addr addr;
struct in_addr mask;
{
	struct in_addr result;

	result.s_addr = addr.s_addr & ~mask.s_addr;
	return result;
}

/*
 - broadcastof - given (network) address and mask, return broadcast address
 */
struct in_addr
broadcastof(addr, mask)
struct in_addr addr;
struct in_addr mask;
{
	struct in_addr result;

	result.s_addr = addr.s_addr | ~mask.s_addr;
	return result;
}
