/*
 * Copyright (C) 2019 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup link_local_ts link_local_ts
 * @ingroup cplugins
 *
 * @defgroup link_local_ts_plugin link_local_ts_plugin
 * @{ @ingroup link_local_ts
 */

#ifndef LINK_LOCAL_TS_PLUGIN_H_
#define LINK_LOCAL_TS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct link_local_ts_plugin_t link_local_ts_plugin_t;

/**
 * RFC 3779 address block checking.
 */
struct link_local_ts_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** LINK_LOCAL_TS_PLUGIN_H_ @}*/
