/* stroke keywords
 * Copyright (C) 2006 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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
 *
 * RCSID $Id: keywords.h,v 1.8 2006/04/17 10:30:27 as Exp $
 */

#ifndef _STROKE_KEYWORDS_H_
#define _STROKE_KEYWORDS_H_

typedef enum {
	STROKE_ADD,
	STROKE_DEL,
	STROKE_DELETE,
	STROKE_ROUTE,
	STROKE_UNROUTE,
	STROKE_UP,
	STROKE_DOWN,
	STROKE_LOGLEVEL,
	STROKE_STATUS,
	STROKE_STATUSALL,
	STROKE_LIST_CERTS,
	STROKE_LIST_CACERTS,
	STROKE_LIST_OCSPCERTS,
	STROKE_LIST_AACERTS,
	STROKE_LIST_ACERTS,
	STROKE_LIST_GROUPS,
	STROKE_LIST_CAINFOS,
	STROKE_LIST_CRLS,
	STROKE_LIST_OCSP,
	STROKE_LIST_ALL,
	STROKE_REREAD_CACERTS,
	STROKE_REREAD_OCSPCERTS,
	STROKE_REREAD_AACERTS,
	STROKE_REREAD_ACERTS,
	STROKE_REREAD_CRLS,
	STROKE_REREAD_ALL,
	STROKE_PURGE_OCSP
} stroke_keyword_t;

#define STROKE_LIST_FIRST		STROKE_LIST_CERTS
#define STROKE_REREAD_FIRST		STROKE_REREAD_CACERTS
#define STROKE_PURGE_FIRST		STROKE_PURGE_OCSP

typedef struct stroke_token stroke_token_t;

extern const stroke_token_t* in_word_set(register const char *str, register unsigned int len);

#endif /* _STROKE_KEYWORDS_H_ */

