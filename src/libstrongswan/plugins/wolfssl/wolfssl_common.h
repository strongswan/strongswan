/*
 * Copyright (C) 2019 Sean Parkinson, wolfSSL Inc.
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

#ifndef WOLFSSL_COMMON_H_
#define WOLFSSL_COMMON_H_

#include <library.h>

/* Undefine these as they are enum entries in wolfSSL - same values */
#ifdef AES_BLOCK_SIZE
#undef AES_BLOCK_SIZE
#endif

#ifdef CAMELLIA_BLOCK_SIZE
#undef CAMELLIA_BLOCK_SIZE
#endif

#ifdef DES_BLOCK_SIZE
#undef DES_BLOCK_SIZE
#endif

/* PARSE_ERROR is an enum entry in wolfSSL - not used in this plugin */
#define PARSE_ERROR	WOLFSSL_PARSE_EROR

#ifndef WOLFSSL_USER_SETTINGS
	#include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>

#undef PARSE_ERROR

#endif /* WOLFSSL_COMMON_H_ */
