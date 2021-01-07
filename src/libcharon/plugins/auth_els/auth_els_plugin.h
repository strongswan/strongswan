/*
 * Copyright (C) 2019-2020 Marvell 
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

/**
 * @defgroup auth_els auth_els
 * @ingroup cplugins
 *
 * @defgroup auth_els_plugin auth_els_plugin
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_PLUGIN_H_
#define AUTH_ELS_PLUGIN_H_

#include <plugins/plugin.h>

#define AUTH_MAJOR_VERSION             1
#define AUTH_MINOR_VERSION             5
#define AUTH_BUILD_VERSION             3
#define AUTH_STRING_SUFFIX_VERSION     "-stub"
#define AUTH_MAX_STRING_VERSION_LEN    32

#define APIDEV_DEVICE	"/dev/ql2xapidev"
#define MEMTRACE_MAX_BACKTRACE_DEPTH   (64)
#define CHARON_EXECUTABLE   "charon"
#define SHELL_BUF_SIZE      512

#define HOST_NO_UNASSIGNED      0xffff

/**
 * Plugin to synchronize state in a high availability cluster.
 */
struct auth_els_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};
typedef struct auth_els_plugin_t auth_els_plugin_t;

#endif /** AUTH_ELS_PLUGIN_H_ @}*/
