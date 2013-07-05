/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup tls_stream tls_stream
 * @ingroup plugins
 *
 * @defgroup tls_stream_plugin tls_stream_plugin
 * @{ @ingroup tls_stream
 */

#ifndef TLS_STREAM_PLUGIN_H_
#define TLS_STREAM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct tls_stream_plugin_t tls_stream_plugin_t;

/**
 * Plugin providing TLS protected streams and stream services.
 */
struct tls_stream_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** TLS_STREAM_PLUGIN_H_ @}*/
