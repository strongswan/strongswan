/*
 * Copyright (c) 2012 Nanoteq Pty Ltd
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
 * @defgroup proposal_keywords proposal_keywords
 * @{ @ingroup crypto
 */

#ifndef PROPOSAL_KEYWORDS_H_
#define PROPOSAL_KEYWORDS_H_

#include <crypto/transform.h>

typedef struct proposal_token proposal_token_t;

/**
 * Class representing a proposal token..
 */
struct proposal_token {

	/**
	 * The name of the token.
	 */
	char *name;

	/**
	 * The type of transform in the token.
	 */
	transform_type_t type;

	/**
	 * The IKE id of the algorithm.
	 */
	u_int16_t algorithm;

	/**
	 * The key size associated with the specific algorithm.
	 */
	u_int16_t keysize;
};

/**
 * Returns a proposal token for the specified string if a token exists.
 *
 * @param str		the string containing the name of the token
 * @return			proposal_tolen if found otherwise NULL
 */
const proposal_token_t* proposal_get_token(const char *str);

#endif /** PROPOSAL_KEYWORDS_H_ @}*/
