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
 * @defgroup auth_els_socket auth_els_socket
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_SOCKET_H_
#define AUTH_ELS_SOCKET_H_

#include <sa/ike_sa.h>
#include <collections/hashtable.h>
#include <network/socket.h>

/**
 * Socket to send/received SA synchronization data
 */
typedef struct auth_els_socket_t auth_els_socket_t;
struct auth_els_socket_t {

	socket_t socket;
};

/**
 * Create a default auth_els_socket instance.
 */
auth_els_socket_t *auth_els_socket_create();

#endif /** AUTH_ELS_SOCKET_ @}*/
