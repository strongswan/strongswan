/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

TEST_VECTOR_CRYPTER(blowfish1)
TEST_VECTOR_CRYPTER(blowfish2)
TEST_VECTOR_CRYPTER(aes_cbc1)
TEST_VECTOR_CRYPTER(aes_cbc2)
TEST_VECTOR_CRYPTER(aes_cbc3)

TEST_VECTOR_SIGNER(aes_xcbc_s1)
TEST_VECTOR_SIGNER(aes_xcbc_s2)
TEST_VECTOR_SIGNER(aes_xcbc_s3)
TEST_VECTOR_SIGNER(aes_xcbc_s4)
TEST_VECTOR_SIGNER(aes_xcbc_s5)

TEST_VECTOR_PRF(aes_xcbc_p1)
TEST_VECTOR_PRF(aes_xcbc_p2)
TEST_VECTOR_PRF(aes_xcbc_p3)
TEST_VECTOR_PRF(aes_xcbc_p4)
TEST_VECTOR_PRF(aes_xcbc_p5)
TEST_VECTOR_PRF(aes_xcbc_p6)
TEST_VECTOR_PRF(aes_xcbc_p7)
