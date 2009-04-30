/*
 * initialize SA ID structure
 * Copyright (C) 2000  Henry Spencer.
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
 - initsaid - initialize SA ID from bits
 */
void
initsaid(addr, spi, proto, dst)
const ip_address *addr;
ipsec_spi_t spi;
int proto;
ip_said *dst;
{
	dst->dst = *addr;
	dst->spi = spi;
	dst->proto = proto;
}
