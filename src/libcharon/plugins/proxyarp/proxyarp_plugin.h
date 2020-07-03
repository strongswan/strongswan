/*
 * Copyright (C) 2008 Martin Willi
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

/*
 * Copyright (C) 2020 Dan James
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Based on strongswan/src/libcharon/plugins/updown for the plugin structure,
 * and PPPd (https://opensource.apple.com/source/ppp/ppp-862) for the
 * interface scanning and route table updates.
 */

/**
 * @defgroup proxyarp proxyarp
 * @ingroup cplugins
 *
 * @defgroup proxyarp_plugin proxyarp_plugin
 * @{ @ingroup proxyarp
 */

#ifndef PROXYARP_PLUGIN_H_
#define PROXYARP_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct proxyarp_plugin_t proxyarp_plugin_t;

/**
 * Proxyarp firewall script invocation plugin, compatible to pluto ones.
 */
struct proxyarp_plugin_t {
	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** PROXYARP_PLUGIN_H_ @}*/
