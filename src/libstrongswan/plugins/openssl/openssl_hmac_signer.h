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
 * @defgroup openssl_hmac_signer openssl_hmac_signer
 * @{ @ingroup openssl_p
 */

#ifndef OPENSSL_HMAC_SIGNER_H_
#define OPENSSL_HMAC_SIGNER_H_

typedef struct openssl_hmac_signer_t openssl_hmac_signer_t;

#include <crypto/signers/signer.h>

/**
 * Implementation of HMAC signature functions using OpenSSL.
 */
struct openssl_hmac_signer_t {

	/**
	 * Implements signer_t interface.
	 */
	signer_t signer;
};

/**
 * Constructor to create openssl_hmac_signer_t.
 *
 * @param algo		algorithm
 * @return			openssl_hmac_signer_t, NULL if not supported
 */
openssl_hmac_signer_t *openssl_hmac_signer_create(integrity_algorithm_t algo);

#endif /** OPENSSL_HMAC_SIGNER_H_ @}*/
