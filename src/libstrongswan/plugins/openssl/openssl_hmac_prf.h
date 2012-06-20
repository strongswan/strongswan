/*
 * Copyright (C) 2012 Aleksandr Grinberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @defgroup openssl_hmac_prf openssl_hmac_prf
 * @{ @ingroup openssl_p
 */

#ifndef OPENSSL_HMAC_PRF_H_
#define OPENSSL_HMAC_PRF_H_

typedef struct openssl_hmac_prf_t openssl_hmac_prf_t;

#include <crypto/prfs/prf.h>

/**
 * Implementation of pseudo random functions using OpenSSL.
 */
struct openssl_hmac_prf_t {
	/**
	 * Implements prf_t interface.
	 */
	prf_t prf_interface;
};

/**
 * Constructor to create openssl_hmac_prf_t.
 *
 * @param algo			algorithm
 * @return			openssl_hmac_prf_t, NULL if not supported
 */
openssl_hmac_prf_t *openssl_hmac_prf_create(pseudo_random_function_t algo);

#endif /** OPENSSL_HMAC_PRF_H_ @}*/
