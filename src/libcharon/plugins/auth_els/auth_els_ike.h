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
 * @defgroup auth_els_ike auth_els_ike
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_IKE_H_
#define AUTH_ELS_IKE_H_

#include <collections/hashtable.h>
#include <sa/ike_sa.h>
#include <daemon.h>

typedef struct auth_els_ike_t auth_els_ike_t;
/**
 * Listener to synchronize IKE_SAs.
 */
struct auth_els_ike_t {

	/**
	 * Implements bus listener interface.
	 */
	listener_t listener;

	/**
	 * Destroy a auth_els_ike_t.
	 */
	void (*destroy)(auth_els_ike_t *this);

};

/**
 * Create a auth_els_ike instance.
 *
 * @param cache			message cache
 * @param cache			List of rport sockets
 * @return				IKE listener
 */
auth_els_ike_t *auth_els_ike_create(auth_els_plugin_t *plugin_ref);

#endif /** AUTH_ELS_IKE_ @}*/
