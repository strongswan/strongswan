/*
 * convert from text form of arbitrary data (e.g., keys) to binary
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

#ifndef TTODATA_H_
#define TTODATA_H_

#include <types.h>

#define	TTODATAV_BUF	40	/* ttodatav's largest non-literal message */
#define TTODATAV_IGNORESPACE  (1<<1)  /* ignore spaces in base64 encodings*/
#define TTODATAV_SPACECOUNTS  0       /* do not ignore spaces in base64   */

err_t ttodata(const char *src, size_t srclen, int base, char *buf, size_t buflen, size_t *needed);


#endif /* TTODATA_H_ */
