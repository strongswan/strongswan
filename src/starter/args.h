/* automatic handling of confread struct arguments
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
 */

#ifndef _ARGS_H_
#define _ARGS_H_

#include "keywords.h"
#include "ipsec-parser.h"

extern char **new_list(char *value);
extern bool assign_arg(kw_token_t token, kw_token_t first, kw_list_t *kw
	, char *base, bool *assigned);
extern void free_args(kw_token_t first, kw_token_t last, char *base);
extern void clone_args(kw_token_t first, kw_token_t last, char *base1
	, char *base2);
extern bool cmp_args(kw_token_t first, kw_token_t last, char *base1
	, char *base2);

#endif /* _ARGS_H_ */

