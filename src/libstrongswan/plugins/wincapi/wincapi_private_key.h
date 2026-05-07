/*
 * Copyright (C) 2018 Robert de la Rey, Francois ten Krooden
 * Copyright (C) 2018 Nanoteq (Pty) Ltd.
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
 * @defgroup wincapi_private_key wincapi_private_key
 * @{ @ingroup wincapi
 */

#ifndef WINCAPI_PRIVATE_KEY_H_
#define WINCAPI_PRIVATE_KEY_H_

#include <credentials/builder.h>
#include <credentials/keys/private_key.h>

typedef struct wincapi_private_key_t wincapi_private_key_t;


/**
 * private_key_t implementation using Windows Certificate Store.
 */
struct wincapi_private_key_t
{
	/**
	 * Implements private_key_t interface
	 */
	private_key_t key;
};


/**
 * Get a handle to a private key stored in the Windows Certificate Store.
 *
 * The function takes BUILD_SUBJECT and optionally a BUILD_PUBLIC_KEY
 * to select a specific key loaded in the store.
 *
 * @param type		type of the key
 * @param args		builder_part_t argument list
 * @return 			built key, NULL on failure
 */
wincapi_private_key_t *wincapi_private_key_get(key_type_t type, va_list args);


#endif /** WINCAPI_PRIVATE_KEY_H_ @}*/

