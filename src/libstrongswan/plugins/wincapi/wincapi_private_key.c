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

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <Wincrypt.h>
#include <ncrypt.h>
#include "wincapi_private_key.h"

typedef struct private_wincapi_private_key_t private_wincapi_private_key_t;


/**
 * Private data of a wincapi_private_key_t object.
 */
struct private_wincapi_private_key_t
{
	/**
	 * Public interface for this signer.
	 */
	wincapi_private_key_t public;

	/**
	 * System store handle
	 */
	HCERTSTORE system_store;

	/**
	 * Certificate context
	 */
	PCCERT_CONTEXT cert_ctx;

	DWORD key_spec;
	bool crypt_or_ncrypt;
	HCRYPTPROV prov;
	HCRYPTKEY key;

	key_type_t key_type;
	DWORD key_len;

	/**
	 * reference count
	 */
	refcount_t ref;

	/**
	 * Associated public key
	 */
	public_key_t *pubkey;

	char *key_container_name;
};


static public_key_t *wincapi_extract_public_key(HCRYPTKEY key);

static HCERTSTORE wincapi_open_certificate_store(short unsigned int *_storename);
static PCCERT_CONTEXT wincapi_get_certificate(HCERTSTORE _store,
		identification_t *_subject);
static char *wincapi_get_container_name(PCCERT_CONTEXT cert);

static HCRYPTPROV wincapi_get_provider_handle(char *_container_name);

static HCRYPTKEY wincapi_get_private_key_handle(HCRYPTPROV prov, DWORD key_spec);
static key_type_t wincapi_get_private_key_type(HCRYPTKEY key);
static DWORD wincapi_get_private_key_len(HCRYPTKEY key);


static char *wide_to_asc(LPCWSTR wstr)
{
	char *str;
	int len_0, sz;

	if (!wstr)
		return NULL;
	len_0 = (int) wcslen(wstr) + 1; /* WideCharToMultiByte expects int */
	sz = WideCharToMultiByte(CP_ACP, 0, wstr, len_0, NULL, 0, NULL, NULL);
	if (!sz)
	{
		return NULL;
	}
	str = malloc(sz);
	if (!str)
	{
		return NULL;
	}
	if (!WideCharToMultiByte(CP_ACP, 0, wstr, len_0, str, sz, NULL, NULL))
	{
		return NULL;
	}
	return str;
}


METHOD(private_key_t, sign, bool,
		private_wincapi_private_key_t *this, signature_scheme_t scheme, void *params,
		chunk_t data, chunk_t *signature)
{
	HCRYPTHASH hash_obj;
	unsigned int alg_id;
	BYTE *buf;
	DWORD buf_len;

	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			alg_id = CALG_SHA1;
			break;
		case SIGN_RSA_EMSA_PKCS1_SHA2_256:
			alg_id = CALG_SHA_256;
			break;
		case SIGN_RSA_EMSA_PKCS1_SHA2_384:
			alg_id = CALG_SHA_384;
			break;
		case SIGN_RSA_EMSA_PKCS1_SHA2_512:
			alg_id = CALG_SHA_512;
			break;
		default:
			return FALSE;
			break;
	}

	if (!CryptCreateHash(this->prov, alg_id, 0, 0, &hash_obj))
	{
		return FALSE;
	}

	if (!CryptHashData(hash_obj, data.ptr, data.len, 0))
	{
		return FALSE;
	}

	if (CryptSignHash(hash_obj, this->key_spec, NULL, 0, NULL, &buf_len))
	{
		buf = (BYTE*) malloc(buf_len);
		if (!CryptSignHash(hash_obj, this->key_spec, NULL, 0, buf, &buf_len))
		{
			return FALSE;
		} else
		{
			/* In-place byte reversal of signature */
			for (int i = 0; i < buf_len / 2; i++)
			{
				unsigned char c;
				c = buf[i];
				buf[i] = buf[buf_len - i - 1];
				buf[buf_len - i - 1] = c;
			}
		}
	} else
	{
		return FALSE;
	}

	if (hash_obj)
	{
		CryptDestroyHash(hash_obj);
	}
	*signature = chunk_create(buf, buf_len);
	return TRUE;
}


METHOD(private_key_t, get_type, key_type_t,
		private_wincapi_private_key_t *this)
{
	return this->key_type;
}


METHOD(private_key_t, decrypt, bool,
		private_wincapi_private_key_t *this, encryption_scheme_t scheme,
		chunk_t crypto, chunk_t *plain)
{
	BYTE *buf;
	DWORD buf_len;

	if (scheme != ENCRYPT_RSA_PKCS1)
	{
		DBG1(DBG_LIB, "encryption scheme %N not supported",
				encryption_scheme_names, scheme);
		return FALSE;
	}

	buf_len = crypto.len;
	buf = (BYTE*) malloc(buf_len);
	memcpy_s(buf, buf_len, crypto.ptr, crypto.len);
	if (!CryptDecrypt(this->key, 0, TRUE, 0, buf, &buf_len))
	{
		return FALSE;
	}

	*plain = chunk_create(buf, buf_len);
	return TRUE;
}


METHOD(private_key_t, get_keysize, int,
		private_wincapi_private_key_t *this)
{
	return this->key_len;
}


METHOD(private_key_t, get_public_key, public_key_t*,
		private_wincapi_private_key_t *this)
{
	return this->pubkey;
}


METHOD(private_key_t, get_encoding, bool,
		private_wincapi_private_key_t *this, cred_encoding_type_t type,
		chunk_t *encoding)
{
	return FALSE;
}


METHOD(private_key_t, get_fingerprint, bool,
		private_wincapi_private_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	return this->pubkey->get_fingerprint(this->pubkey, type, fp);
}


METHOD(private_key_t, get_ref, private_key_t*,
		private_wincapi_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}


METHOD(private_key_t, destroy, void,
		private_wincapi_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (this->pubkey)
		{
			this->pubkey->destroy(this->pubkey);
		}
		if (this->key)
		{
			CryptDestroyKey(this->key);
		}
		if (this->prov)
		{
			CryptReleaseContext(this->prov, 0);
		}
		if (this->cert_ctx)
		{
			CertFreeCertificateContext(this->cert_ctx);
		}
		if (this->system_store)
		{
			CertCloseStore(this->system_store, CERT_CLOSE_STORE_CHECK_FLAG);
		}
		if (this->key_container_name)
		{
			free(this->key_container_name);
		}
	}
}


/**
 * See header.
 */
wincapi_private_key_t *wincapi_private_key_get(key_type_t type, va_list args)
{
	private_wincapi_private_key_t *this;
	identification_t *subject = NULL;
	chunk_t data = chunk_empty;

	while (TRUE)
	{
		builder_part_t build_part = va_arg(args, builder_part_t);
		switch (build_part)
		{
			case BUILD_BLOB_PEM:
				data = va_arg(args, chunk_t);
				subject = identification_create_from_string(data.ptr);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!subject)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.belongs_to = private_key_belongs_to,
				.equals = private_key_equals,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.system_store = NULL,
		.cert_ctx = NULL,
		.key_spec = AT_KEYEXCHANGE,
		.crypt_or_ncrypt = FALSE,
		.prov = 0,
		.key = 0,
		.key_type = 0,
		.key_len = 0,
		.ref = 1,
		.pubkey = NULL,
		.key_container_name = 0,
	);

	this->system_store = wincapi_open_certificate_store(L"MY");
	if (!this->system_store)
	{
		DBG1(DBG_CFG, "Failed to open windows certificate store.");
		destroy(this);
		return NULL;
	}

	this->cert_ctx = wincapi_get_certificate(this->system_store, subject);
	if (!this->cert_ctx)
	{
		DBG1(DBG_CFG,
				"Failed to retrieve certificate (%Y) from the windows certificate store.",
				subject);
		destroy(this);
		return NULL;
	}

	this->key_container_name = wincapi_get_container_name(this->cert_ctx);
	if (!this->key_container_name)
	{
		DBG1(DBG_CFG,
				"Failed to retrieve private key container name from the windows certificate store.");
		destroy(this);
		return NULL;
	}

	this->prov = wincapi_get_provider_handle(this->key_container_name);
	if (!this->prov)
	{
		DBG1(DBG_CFG,
				"Failed to retrieve private key provider from the windows certificate store.");
		destroy(this);
		return NULL;
	}

	this->key = wincapi_get_private_key_handle(this->prov, this->key_spec);
	if (!this->key)
	{
		DBG1(DBG_CFG,
				"Failed to retrieve private key handle from the windows certificate store.");
		destroy(this);
		return NULL;
	}
	this->key_type = wincapi_get_private_key_type(this->key);
	this->key_len = wincapi_get_private_key_len(this->key);

	this->pubkey = wincapi_extract_public_key(this->key);
	if (!this->pubkey)
	{
		DBG1(DBG_CFG, "Failed to create public key from private key.");
		destroy(this);
		return NULL;
	}

	return &this->public;
}


static HCERTSTORE wincapi_open_certificate_store(short unsigned int *_storename)
{
	HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
			CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
			_storename);
	return store;
}


static PCCERT_CONTEXT wincapi_get_certificate(HCERTSTORE _store,
		identification_t *_subject)
{
	char buf[BUF_LEN];
	PCCERT_CONTEXT cert_ctx = NULL;
	CERT_NAME_BLOB encoded_name;

	snprintf(buf, BUF_LEN, "%Y", _subject);

	if (strlen(buf) != 0)
	{
		if (CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf,
				CERT_X500_NAME_STR, NULL, NULL, &encoded_name.cbData, NULL))
		{
			encoded_name.pbData = (LPBYTE) malloc(encoded_name.cbData);
			if (encoded_name.pbData)
			{
				if (CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf,
						CERT_X500_NAME_STR, NULL, encoded_name.pbData,
						&encoded_name.cbData, NULL))
				{
					cert_ctx = CertFindCertificateInStore(_store,
							X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
							CERT_FIND_SUBJECT_NAME, &encoded_name, NULL);
				}
				free(encoded_name.pbData);
			}
		}
	}
	return cert_ctx;
}


static char *wincapi_get_container_name(PCCERT_CONTEXT cert)
{
	char *container_name = 0;
	DWORD len = 0;
	CRYPT_KEY_PROV_INFO *pinfo = NULL;

	if (!CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
			NULL, &len))
		return FALSE;
	pinfo = (CRYPT_KEY_PROV_INFO *) malloc(len);
	if (pinfo)
	{
		if (CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID,
				pinfo, &len))
		{
			container_name = wide_to_asc(pinfo->pwszContainerName);
		}
		free(pinfo);
	}
	return container_name;
}


static HCRYPTPROV wincapi_get_provider_handle(char *container_name)
{
	HCRYPTPROV prov = 0;
	CryptAcquireContext(&(prov), container_name, MS_ENH_RSA_AES_PROV,
			PROV_RSA_AES, CRYPT_MACHINE_KEYSET);
	return prov;
}


static HCRYPTKEY wincapi_get_private_key_handle(HCRYPTPROV prov, DWORD key_spec)
{
	HCRYPTKEY key = 0;
	CryptGetUserKey(prov, key_spec, &key);
	return key;
}


static key_type_t wincapi_get_private_key_type(HCRYPTKEY key)
{
	key_type_t key_type = KEY_ANY;
	unsigned int alg_id = 0;
	DWORD out_len = 0;

	out_len = sizeof(alg_id);
	CryptGetKeyParam(key, KP_ALGID, (BYTE*) (&alg_id), &out_len, 0);

	switch (alg_id)
	{
		case CALG_RSA_KEYX:
			case CALG_RSA_SIGN:
			key_type = KEY_RSA;
			break;
		case CALG_DSS_SIGN:
			key_type = KEY_DSA;
			break;
#if NTDDI_VERSION >= 0x06000000
			case CALG_ECDSA:
			key_type = KEY_ECDSA;
			break;
#endif
	}
	return key_type;
}


static DWORD wincapi_get_private_key_len(HCRYPTKEY key)
{
	DWORD key_len = 0;
	DWORD out_len = sizeof(key_len);
	CryptGetKeyParam(key, KP_KEYLEN, (BYTE*) (&key_len), &out_len, 0);

	return key_len;
}


/*
 * Export the public key from the private key part.
 */
static public_key_t *wincapi_extract_public_key(HCRYPTKEY key)
{
	public_key_t *public = NULL;
	DWORD len = 0;
	unsigned char *pubkey = NULL;
	BLOBHEADER *bh;

	if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &len))
	{
		DBG1(DBG_CFG, "Unable to export public key from private key.");
		return public;
	}
	pubkey = (BYTE*) malloc(len);
	if (pubkey)
	{
		if (CryptExportKey(key, 0, PUBLICKEYBLOB, 0, pubkey, &len))
		{
			bh = (BLOBHEADER *) pubkey;
			if ((bh->bType == PUBLICKEYBLOB)
					&& (bh->aiKeyAlg == CALG_RSA_SIGN
							|| bh->aiKeyAlg == CALG_RSA_KEYX))
			{
				RSAPUBKEY *rsapubkey;
				chunk_t n, e;
				DWORD rsa_modlen;
				unsigned char *rsa_modulus;

				rsapubkey = (RSAPUBKEY *) (bh + 1);
				if (rsapubkey->magic != 0x31415352)
				{
					DBG1(DBG_CFG, "RSA Pubkey Magic invalid.");
				}

				rsa_modulus = (unsigned char *) (rsapubkey + 1);
				rsa_modlen = rsapubkey->bitlen / 8 + 1;

				e = chunk_create(&rsapubkey->pubexp, sizeof(rsapubkey->pubexp));
				// Swap the byte order, since windows is stupid for some reason
				for (int i = 0; i < e.len / 2; i++)
				{
					unsigned char c;
					c = e.ptr[i];
					e.ptr[i] = e.ptr[e.len - i - 1];
					e.ptr[e.len - i - 1] = c;
				}

				n = chunk_create(rsa_modulus, rsa_modlen);
				// Swap the byte order, since windows is stupid for some reason
				for (int i = 0; i < n.len / 2; i++)
				{
					unsigned char c;
					c = n.ptr[i];
					n.ptr[i] = n.ptr[n.len - i - 1];
					n.ptr[n.len - i - 1] = c;
				}

				public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY,
						KEY_RSA,
						BUILD_RSA_MODULUS, n, BUILD_RSA_PUB_EXP, e, BUILD_END);
			}
		}
		free(pubkey);
	}
	return public;
}
