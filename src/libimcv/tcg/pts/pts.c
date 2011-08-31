/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
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

#include "pts.h"

#include <debug.h>
#include <crypto/hashers/hasher.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <curl/curl.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <dirent.h>
#include <errno.h>

#include "fake_ek_cert.h"

#define PTS_BUF_SIZE	32768

/* Size of endorsement key in bytes */
#define	EKSIZE		(2048/8)
/* URL of Privacy CA */
#define CAURL		"http://www.privacyca.com/"
#define CERTURL		CAURL "api/pca/level%d?ResponseFormat=PEM"
#define REQURL		CAURL "api/pca/level%d?ResponseFormat=Binary"

/* TPM has EK Certificate */
/* #define REALEK */

typedef struct private_pts_t private_pts_t;

/**
 * Private data of a pts_t object.
 *
 */
struct private_pts_t {

	/**
	 * Public pts_t interface.
	 */
	pts_t public;

	/**
	 * PTS Protocol Capabilities
	 */
	pts_proto_caps_flag_t proto_caps;

	/**
	 * PTS Measurement Algorithm
	 */
	pts_meas_algorithms_t algorithm;

	/**
	 * Do we have an activated TPM
	 */
	bool has_tpm;

	/**
	 * Contains a TPM_CAP_VERSION_INFO struct
	 */
	chunk_t tpm_version_info;
	
	/**
	 * Contains a Attestation Identity Key
	 */
	chunk_t aik;
	
	/**
	 * True if AIK is naked public key, not a certificate
	 */
	bool is_naked_key;
	
};

METHOD(pts_t, get_proto_caps, pts_proto_caps_flag_t,
	private_pts_t *this)
{
	return this->proto_caps;
}

METHOD(pts_t, set_proto_caps, void,
	private_pts_t *this, pts_proto_caps_flag_t flags)
{
	this->proto_caps = flags;
	DBG2(DBG_TNC, "supported PTS protocol capabilities: %s%s%s%s%s",
				   flags & PTS_PROTO_CAPS_C ? "C" : ".",
				   flags & PTS_PROTO_CAPS_V ? "V" : ".",
				   flags & PTS_PROTO_CAPS_D ? "D" : ".",
				   flags & PTS_PROTO_CAPS_T ? "T" : ".",
				   flags & PTS_PROTO_CAPS_X ? "X" : ".");
}

METHOD(pts_t, get_meas_algorithm, pts_meas_algorithms_t,
	private_pts_t *this)
{
	return this->algorithm;
}

METHOD(pts_t, set_meas_algorithm, void,
	private_pts_t *this, pts_meas_algorithms_t algorithm)
{
	hash_algorithm_t hash_alg;

	hash_alg = pts_meas_to_hash_algorithm(algorithm);
	DBG2(DBG_TNC, "selected PTS measurement algorithm is %N",
				   hash_algorithm_names, hash_alg);
	if (hash_alg != HASH_UNKNOWN)
	{
		this->algorithm = algorithm;
	}
}

/**
 * Print TPM 1.2 Version Info
 */
static void print_tpm_version_info(private_pts_t *this)
{
	TPM_CAP_VERSION_INFO versionInfo;
	UINT64 offset = 0;
	TSS_RESULT result;

	result = Trspi_UnloadBlob_CAP_VERSION_INFO(&offset,
						 	this->tpm_version_info.ptr, &versionInfo);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_TNC, "could not parse tpm version info: tss error 0x%x",
			 result);
	}
	else
	{
		DBG2(DBG_TNC, "TPM 1.2 Version Info: Chip Version: %hhu.%hhu.%hhu.%hhu,"
			 " Spec Level: %hu, Errata Rev: %hhu, Vendor ID: %.4s",
			 versionInfo.version.major, versionInfo.version.minor,
			 versionInfo.version.revMajor, versionInfo.version.revMinor,
			 versionInfo.specLevel, versionInfo.errataRev, 
			 versionInfo.tpmVendorID);
	}
}

METHOD(pts_t, get_tpm_version_info, bool,
	private_pts_t *this, chunk_t *info)
{
	if (!this->has_tpm)
	{
		return FALSE;
	}
	*info = this->tpm_version_info;
	print_tpm_version_info(this);
	return TRUE;
}

METHOD(pts_t, set_tpm_version_info, void,
	private_pts_t *this, chunk_t info)
{
	this->tpm_version_info = chunk_clone(info);
	print_tpm_version_info(this);
}

/**
 * Create a fake endorsement key cert using system's actual EK 
 */

static bool makeEKCert(TSS_HCONTEXT hContext, TSS_HTPM hTPM, UINT32 *pCertLen, BYTE **pCert)
{
	TSS_RESULT	result;
	TSS_HKEY	hPubek;
	UINT32		modulusLen;
	BYTE		*modulus;

	result = Tspi_TPM_GetPubEndorsementKey (hTPM, TRUE, NULL, &hPubek);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_GetAttribData (hPubek, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulusLen, &modulus);
	Tspi_Context_CloseObject (hContext, hPubek);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	if (modulusLen != 256) {
		Tspi_Context_FreeMemory (hContext, modulus);
		goto err;
	}
	*pCertLen = sizeof(fakeEKCert);
	*pCert = malloc (*pCertLen);
	memcpy (*pCert, fakeEKCert, *pCertLen);
	memcpy (*pCert + 0xc6, modulus, modulusLen);
	Tspi_Context_FreeMemory (hContext, modulus);

	return TRUE;

err:
	DBG1(DBG_TNC, "TPM not available: tss error 0x%x", result);
	return FALSE;
}

/** 
 * Read the level N CA from privacyca.com 
 * Assume Curl library has been initialized 
 */

static X509* readPCAcert (int level)
{
	CURL		*hCurl;
	char		url[128];
	FILE		*f_tmp = tmpfile();
	X509		*x509;
	int		result;

	hCurl = curl_easy_init ();
	DBG1(DBG_IMC, url, CERTURL, level);
	curl_easy_setopt (hCurl, CURLOPT_URL, url);
	curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (BYTE **)f_tmp);

	if ((result = curl_easy_perform(hCurl))) {
		DBG1(DBG_IMC, "Unable to connect to Privacy CA, curl library result code %d\n", result);
		fclose(f_tmp);
		return NULL;
	}

	rewind (f_tmp);
	x509 = PEM_read_X509 (f_tmp, NULL, NULL, NULL);
	fclose(f_tmp);

	return x509;
}


/**
 * Obtain an AIK, SRK and TPM Owner secret has to be both set to well known secret
 * of 20 bytes of zero
 */
static bool obtain_aik(chunk_t *aik, bool *is_naked_key)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hPCAKey;
	TSS_HKEY	hIdentKey;
	TSS_HPOLICY	hSrkPolicy;
	TSS_HPOLICY	hTPMPolicy;
	TSS_UUID	SRK_UUID = TSS_UUID_SRK;
	BYTE		secret[] = TSS_WELL_KNOWN_SECRET;
	X509		*x509;
	EVP_PKEY	*pcaKey;
	RSA		*rsa = NULL;
	CURL		*hCurl;
	struct curl_slist *slist = NULL;
	BYTE		n[16384/8];
	int		size_n;
	FILE		*f_tmp;
	BYTE		*rgbTCPAIdentityReq;
	UINT32		ulTCPAIdentityReqLength;
	UINT32		initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
					TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;
	BYTE		asymBuf[EKSIZE];
	BYTE		*symBuf;
	BYTE		*credBuf;
	BYTE		*tbuf;
	UINT32		asymBufSize;
	UINT32		symBufSize;
	UINT32		credBufSize;
	BYTE		*blob;
	UINT32		blobLen;
#ifdef REALEK
	const int	level = 1;
#else
	const int	level = 0;
	BYTE		*ekCert = NULL;
	UINT32		ekCertLen;
#endif
	char		url[128];
	int		result;
	
	*aik = chunk_empty;
	*is_naked_key = false;
	
	curl_global_init (CURL_GLOBAL_ALL);
	DBG3(DBG_IMC, "Retrieving PCA certificate...\n");

	x509 = readPCAcert (level);
	if (x509 == NULL) {
		DBG1(DBG_IMC, "Error reading PCA key\n");
		goto err;
	}
	pcaKey = X509_get_pubkey(x509);
	rsa = EVP_PKEY_get1_RSA(pcaKey);
	if (rsa == NULL) {
		DBG1(DBG_IMC, "Error reading RSA key from PCA\n");
		goto err;
	}
	X509_free (x509);

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_Create\n", result);
		goto err;
	}
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_Connect\n", result);
		goto err;
	}
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_GetTpmObject\n", result);
		goto err;
	}
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_LoadKeyByUUID for SRK\n", result);
		goto err;
	}
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_GetPolicyObject for SRK\n", result);
		goto err;
	}
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1, 20, secret);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Policy_SetSecret for SRK\n", result);
		goto err;
	}
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_GetPolicyObject for TPM\n", result);
		goto err;
	}
	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_SHA1, 20, secret);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Policy_SetSecret for TPM\n", result);
		goto err;
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hIdentKey);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_CreateObject for key\n", result);
		goto err;
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hPCAKey);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Context_CreateObject for PCA\n", result);
		goto err;
	}
	if ((size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		printf("BN_bn2bin failed\n");
                goto err;;
        }
	result = Tspi_SetAttribData (hPCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, size_n, n);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_SetAttribData for PCA modulus\n", result);
		goto err;
	}
	result = Tspi_SetAttribUint32(hPCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				      TSS_ES_RSAESPKCSV15);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_SetAttribUint32 for PCA encscheme\n", result);
		goto err;
	}

#ifndef REALEK
	result = makeEKCert(hContext, hTPM, &ekCertLen, &ekCert);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on makeEKCert\n", result);
		goto err;
	}

	result = Tspi_SetAttribData(hTPM, TSS_TSPATTRIB_TPM_CREDENTIAL,
			TSS_TPMATTRIB_EKCERT, ekCertLen, ekCert);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on SetAttribData for EKCert\n", result);
		goto err;
	}
#endif

	DBG3(DBG_IMC, "Generating attestation identity key...\n");
	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCAKey, 0,
						 NULL, hIdentKey, TSS_ALG_AES,
						 &ulTCPAIdentityReqLength,
						 &rgbTCPAIdentityReq);
	if (result != TSS_SUCCESS){
		DBG1(DBG_IMC, "Error 0x%x on Tspi_TPM_CollateIdentityRequest\n", result);
		goto err;
	}

	DBG3(DBG_IMC, "Sending request to PrivacyCA.com...\n");

	/* Send to server */
	f_tmp = tmpfile();
	hCurl = curl_easy_init ();
	DBG3(DBG_IMC, "URL: %s\nRequest URL: %s\n Certificate Level: %d", url, REQURL, level);
	curl_easy_setopt (hCurl, CURLOPT_URL, url);
	curl_easy_setopt (hCurl, CURLOPT_POSTFIELDS, (void *)rgbTCPAIdentityReq);
	curl_easy_setopt (hCurl, CURLOPT_POSTFIELDSIZE, ulTCPAIdentityReqLength);
	curl_easy_setopt (hCurl, CURLOPT_WRITEDATA, (BYTE **)f_tmp);
	slist = curl_slist_append (slist, "Pragma: no-cache");
	slist = curl_slist_append (slist, "Content-Type: application/octet-stream");
	slist = curl_slist_append (slist, "Content-Transfer-Encoding: binary");
	curl_easy_setopt (hCurl, CURLOPT_HTTPHEADER, slist);
	if ((result = curl_easy_perform(hCurl))) {
		DBG1(DBG_IMC, "Unable to connect to Privacy CA, curl library result code %d\n", result);
		exit (result);
	}
	curl_slist_free_all(slist);

	DBG3(DBG_IMC, "Processing response from PrivacyCA...\n");

	fflush (f_tmp);
	symBufSize = ftell(f_tmp);
	symBuf = malloc(symBufSize);
	rewind(f_tmp);
	if(!fread (symBuf, 1, symBufSize, f_tmp))
	{
		DBG1(DBG_IMC, "Failed to read buffer\n");
		goto err;
	}
	
	fclose (f_tmp);

	asymBufSize = sizeof(asymBuf);
	if (symBufSize <= asymBufSize)
	{
		DBG1(DBG_IMC, "Bad response from PrivacyCA.com: %s\n", symBuf);
		goto err;
	}

	memcpy (asymBuf, symBuf, asymBufSize);
	symBufSize -= asymBufSize;
	symBuf += asymBufSize;

	result = Tspi_Key_LoadKey (hIdentKey, hSRK);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_Key_LoadKey for AIK\n", result);
		goto err;
	}

	result = Tspi_TPM_ActivateIdentity (hTPM, hIdentKey, asymBufSize, asymBuf,
						symBufSize, symBuf,
						&credBufSize, &credBuf);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_TPM_ActivateIdentity\n", result);
		goto err;
	}

	/* Output key blob */
	result = Tspi_GetAttribData (hIdentKey, TSS_TSPATTRIB_KEY_BLOB,
		TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
	if (result != TSS_SUCCESS) {
		DBG1(DBG_IMC, "Error 0x%x on Tspi_GetAttribData for key blob\n", result);
		goto err;
	}

	/* TODO: Do something with blob variable */

	Tspi_Context_FreeMemory (hContext, blob);

	/* Output credential in PEM format */
	tbuf = credBuf;
	x509 = d2i_X509(NULL, (const BYTE **)&tbuf, credBufSize);
	if (x509 == NULL) {
		DBG1(DBG_IMC, "Unable to parse returned credential\n");
		goto err;
	}
	if (tbuf-credBuf != credBufSize) {
		DBG1(DBG_IMC, "Note, not all data from privacy ca was parsed correctly\n");
	}
	
	/* TODO: Do something with X509 object */
	X509_free (x509);

	DBG3(DBG_IMC, "Succeeded at obtaining AIK Certificate from Privacy CA!\n");
	return TRUE;
	
err:
	return FALSE;
}

METHOD(pts_t, get_aik, bool,
	private_pts_t *this, chunk_t *aik, bool *is_naked_key)
{
	if(obtain_aik(aik, is_naked_key) != TSS_SUCCESS )
	{
		return FALSE;
	}
	
	*aik = this->aik;
	*is_naked_key = this->is_naked_key;
	
	return TRUE;
}

METHOD(pts_t, set_aik, void,
	private_pts_t *this, chunk_t aik, bool is_naked_key)
{
	this->aik = chunk_clone(aik);
	this->is_naked_key = is_naked_key;
}

METHOD(pts_t, hash_file, bool,
	private_pts_t *this, chunk_t path, chunk_t *out)
{
	char buffer[PTS_BUF_SIZE];
	FILE *file;
	int bytes_read;
	hasher_t *hasher;
	hash_algorithm_t hash_alg;
	
	/* Create a hasher */
	hash_alg = pts_meas_to_hash_algorithm(this->algorithm);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
	if (!hasher)
	{
		DBG1(DBG_IMC, "hasher %N not available", hash_algorithm_names, hash_alg);
		return false;
	}

	file = fopen(path.ptr, "rb");
	if (!file)
	{
		DBG1(DBG_IMC,"file '%s' can not be opened, %s", path.ptr, strerror(errno));
		hasher->destroy(hasher);
		return false;
	}
	while (TRUE)
	{
		bytes_read = fread(buffer, 1, sizeof(buffer), file);
		if (bytes_read > 0)
		{
			hasher->allocate_hash(hasher, chunk_create(buffer, bytes_read), NULL);
		}
		else
		{
			hasher->allocate_hash(hasher, chunk_empty, out);
			break;
		}
	}
		
	fclose(file);
	hasher->destroy(hasher);

	return true;
}

METHOD(pts_t, hash_directory, bool,
	private_pts_t *this, chunk_t path, linked_list_t **file_measurements)
{
	DIR *dir;
	struct dirent *ent;
	file_meas_entry_t *entry;
	linked_list_t *list = *file_measurements;
	
	list = linked_list_create();
	entry = malloc_thing(file_meas_entry_t);
	
	dir = opendir(path.ptr);
	if (dir == NULL)
	{
		DBG1(DBG_IMC, "opening directory '%s' failed: %s", path.ptr, strerror(errno));
		return false;
	}
	while ((ent = readdir(dir)))
	{
		if (*ent->d_name == '.')
		{	/* skip ".", ".." and hidden files (such as ".svn") */
			continue;
		}
				
		if(this->public.hash_file(&this->public, chunk_cat("cc", path, chunk_create(ent->d_name, strlen(ent->d_name)))
			, &entry->measurement) != true)
		{
			DBG1(DBG_IMC, "Hashing the given file has failed");
			return false;
		}
		
		entry->file_name_len = strlen(ent->d_name);
		entry->file_name = chunk_create(ent->d_name,strlen(ent->d_name));
		
		list->insert_last(list,entry);
	}
		
	closedir(dir);
	
	*file_measurements = list;
	return true;
}

METHOD(pts_t, destroy, void,
	private_pts_t *this)
{
	free(this->tpm_version_info.ptr);
	free(this);
}

/**
 * Check for a TPM by querying for TPM Version Info
 */
static bool has_tpm(private_pts_t *this)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_VERSION_VAL,  0, NULL,
									&this->tpm_version_info.len,
									&this->tpm_version_info.ptr);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	this->tpm_version_info = chunk_clone(this->tpm_version_info);
	return TRUE;

err:
	DBG1(DBG_TNC, "TPM not available: tss error 0x%x", result);
	return FALSE;
}

/**
 * See header
 */
pts_t *pts_create(bool is_imc)
{
	private_pts_t *this;

	INIT(this,
		.public = {
			.get_proto_caps = _get_proto_caps,
			.set_proto_caps = _set_proto_caps,
			.get_meas_algorithm = _get_meas_algorithm,
			.set_meas_algorithm = _set_meas_algorithm,
			.get_tpm_version_info = _get_tpm_version_info,
			.set_tpm_version_info = _set_tpm_version_info,
			.get_aik = _get_aik,
			.set_aik = _set_aik,
			.hash_file = _hash_file,
			.hash_directory = _hash_directory,
			.destroy = _destroy,
		},
		.proto_caps = PTS_PROTO_CAPS_V,
		.algorithm = PTS_MEAS_ALGO_SHA256,
	);

	if (is_imc)
	{
		if (has_tpm(this))
		{
			this->has_tpm = TRUE;
			this->proto_caps |= PTS_PROTO_CAPS_T;
		}
	}
	else
	{
		this->proto_caps |= PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_C;
	}

	return &this->public;
}

