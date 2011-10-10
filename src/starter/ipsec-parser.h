/* strongSwan config file parser
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef _IPSEC_PARSER_H_
#define _IPSEC_PARSER_H_

#include "keywords.h"

typedef struct kw_entry kw_entry_t;

struct kw_entry {
	char *name;
	kw_token_t token;
};

typedef struct kw_list kw_list_t;

struct kw_list {
		kw_entry_t *entry;
		char *value;
		kw_list_t *next;
};

typedef struct section_list section_list_t;

struct section_list {
		char *name;
		kw_list_t *kw;
		section_list_t *next;
};

typedef struct config_parsed config_parsed_t;

struct config_parsed {
		kw_list_t *config_setup;
		section_list_t *conn_first, *conn_last;
		section_list_t *ca_first, *ca_last;
};

config_parsed_t *parser_load_conf (const char *file);
void parser_free_conf (config_parsed_t *cfg);

#endif /* _IPSEC_PARSER_H_ */

