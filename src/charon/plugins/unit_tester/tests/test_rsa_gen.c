/*
 * Copyright (C) 2008 Martin Willi
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

#include <library.h>
#include <daemon.h>

/*******************************************************************************
 * RSA key generation and signature
 ******************************************************************************/
bool test_rsa_gen()
{
	char buf[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	chunk_t data = chunk_from_buf(buf), sig;
	private_key_t *private;
	public_key_t *public;
	u_int key_size;
	
	for (key_size = 512; key_size <= 2048; key_size *= 2)
	{
		private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
									 BUILD_KEY_SIZE, key_size, BUILD_END);
		if (!private)
		{
			DBG1(DBG_CFG, "generating %d bit RSA key failed");
			return FALSE;
		}
		public = private->get_public_key(private);
		if (!public)
		{
			DBG1(DBG_CFG, "generating public from private key failed");
			return FALSE;
		}
		if (!private->sign(private, SIGN_RSA_EMSA_PKCS1_SHA1, data, &sig))
		{
			DBG1(DBG_CFG, "creating RSA signature failed");
			return FALSE;
		}
		if (!public->verify(public, SIGN_RSA_EMSA_PKCS1_SHA1, data, sig))
		{
			DBG1(DBG_CFG, "verifying RSA signature failed");
			return FALSE;
		}
		sig.ptr[sig.len-1]++;
		if (public->verify(public, SIGN_RSA_EMSA_PKCS1_SHA1, data, sig))
		{
			DBG1(DBG_CFG, "verifying faked RSA signature succeeded!");
			return FALSE;
		}
		free(sig.ptr);
		public->destroy(public);
		private->destroy(private);
	}
	return TRUE;
}

