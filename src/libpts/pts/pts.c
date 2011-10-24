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
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>
/* for isdigit()*/
#include <ctype.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define PTS_BUF_SIZE	4096

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
	 * DH Hash Algorithm
	 */
	pts_meas_algorithms_t dh_hash_algorithm;

	/**
	 * PTS Diffie-Hellman Secret
	 */
	diffie_hellman_t *dh;

	/**
	 * PTS Diffie-Hellman Initiator Nonce
	 */
	chunk_t initiator_nonce;

	/**
	 * PTS Diffie-Hellman Responder Nonce
	 */
	chunk_t responder_nonce;

	/**
	 * Secret assessment value to be used for TPM Quote as an external data
	 */
	chunk_t secret;

	/**
	 * Platform and OS Info
	 */
	char *platform_info;

	/**
	 * TRUE if IMC-PTS, FALSE if IMV-PTS
	 */
	bool is_imc;

	/**
	 * Do we have an activated TPM
	 */
	bool has_tpm;

	/**
	 * Contains a TPM_CAP_VERSION_INFO struct
	 */
	chunk_t tpm_version_info;

	/**
	 * Contains TSS Blob structure for AIK
	 */
	chunk_t aik_blob;

	/**
	 * Contains a Attestation Identity Key or Certificate
	 */
 	certificate_t *aik;

	/**
	 * List of extended PCR's with corresponding values
	 */
	linked_list_t *pcrs;
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
	DBG2(DBG_PTS, "supported PTS protocol capabilities: %s%s%s%s%s",
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

	hash_alg = pts_meas_algo_to_hash(algorithm);
	DBG2(DBG_PTS, "selected PTS measurement algorithm is %N",
				   hash_algorithm_names, hash_alg);
	if (hash_alg != HASH_UNKNOWN)
	{
		this->algorithm = algorithm;
	}
}

METHOD(pts_t, get_dh_hash_algorithm, pts_meas_algorithms_t,
	private_pts_t *this)
{
	return this->dh_hash_algorithm;
}

METHOD(pts_t, set_dh_hash_algorithm, void,
	private_pts_t *this, pts_meas_algorithms_t algorithm)
{
	hash_algorithm_t hash_alg;

	hash_alg = pts_meas_algo_to_hash(algorithm);
	DBG2(DBG_PTS, "selected DH hash algorithm is %N",
				   hash_algorithm_names, hash_alg);
	if (hash_alg != HASH_UNKNOWN)
	{
		this->dh_hash_algorithm = algorithm;
	}
}


METHOD(pts_t, create_dh_nonce, bool,
	private_pts_t *this, pts_dh_group_t group, int nonce_len)
{
	diffie_hellman_group_t dh_group;
	chunk_t *nonce;
	rng_t *rng;

	dh_group = pts_dh_group_to_ike(group);
	DBG2(DBG_PTS, "selected PTS DH group is %N",
				   diffie_hellman_group_names, dh_group);
	DESTROY_IF(this->dh);
	this->dh = lib->crypto->create_dh(lib->crypto, dh_group);

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_PTS, "no rng available");
		return FALSE;
	}
	DBG2(DBG_PTS, "nonce length is %d", nonce_len);
	nonce = this->is_imc ? &this->responder_nonce : &this->initiator_nonce;
	chunk_free(nonce);
	rng->allocate_bytes(rng, nonce_len, nonce);
	rng->destroy(rng);

	return TRUE;
}

METHOD(pts_t, get_my_public_value, void,
	private_pts_t *this, chunk_t *value, chunk_t *nonce)
{
	this->dh->get_my_public_value(this->dh, value);
	*nonce = this->is_imc ? this->responder_nonce : this->initiator_nonce;
}

METHOD(pts_t, set_peer_public_value, void,
	private_pts_t *this, chunk_t value, chunk_t nonce)
{
	this->dh->set_other_public_value(this->dh, value);

	nonce = chunk_clone(nonce);
	if (this->is_imc)
	{
		this->initiator_nonce = nonce;
	}
	else
	{
		this->responder_nonce = nonce;
	}
}

METHOD(pts_t, calculate_secret, bool,
	private_pts_t *this)
{
	hasher_t *hasher;
	hash_algorithm_t hash_alg;
	chunk_t shared_secret;

	/* Check presence of nonces */
	if (!this->initiator_nonce.len || !this->responder_nonce.len)
	{
		DBG1(DBG_PTS, "initiator and/or responder nonce is not available");
		return FALSE;
	}
	DBG3(DBG_PTS, "initiator nonce: %B", &this->initiator_nonce);
	DBG3(DBG_PTS, "responder nonce: %B", &this->responder_nonce);

	/* Calculate the DH secret */
	if (this->dh->get_shared_secret(this->dh, &shared_secret) != SUCCESS)
	{
		DBG1(DBG_PTS, "shared DH secret computation failed");
		return FALSE;
	}
	DBG4(DBG_PTS, "shared DH secret: %B", &shared_secret);

	/* Calculate the secret assessment value */
	hash_alg = pts_meas_algo_to_hash(this->dh_hash_algorithm);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);

	hasher->allocate_hash(hasher, chunk_from_chars('1'), NULL);
	hasher->allocate_hash(hasher, this->initiator_nonce, NULL);
	hasher->allocate_hash(hasher, this->responder_nonce, NULL);
	hasher->allocate_hash(hasher, shared_secret, &this->secret);
	hasher->destroy(hasher);

	/* The DH secret must be destroyed */
	chunk_clear(&shared_secret);

	/*
	 * Truncate the hash to 20 bytes to fit the ExternalData
	 * argument of the TPM Quote command
	 */
	this->secret.len = min(this->secret.len, 20);
	DBG4(DBG_PTS, "secret assessment value: %B", &this->secret);
	return TRUE;
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
		DBG1(DBG_PTS, "could not parse tpm version info: tss error 0x%x",
			 result);
	}
	else
	{
		DBG2(DBG_PTS, "TPM 1.2 Version Info: Chip Version: %hhu.%hhu.%hhu.%hhu,"
					  " Spec Level: %hu, Errata Rev: %hhu, Vendor ID: %.4s",
					  versionInfo.version.major, versionInfo.version.minor,
					  versionInfo.version.revMajor, versionInfo.version.revMinor,
					  versionInfo.specLevel, versionInfo.errataRev,
					  versionInfo.tpmVendorID);
	}
}

METHOD(pts_t, get_platform_info, char*,
	private_pts_t *this)
{
	return this->platform_info;
}

METHOD(pts_t, set_platform_info, void,
	private_pts_t *this, char *info)
{
	free(this->platform_info);
	this->platform_info = strdup(info);
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
 * Load an AIK Blob (TSS_TSPATTRIB_KEYBLOB_BLOB attribute)
 */
static void load_aik_blob(private_pts_t *this)
{
	char *blob_path;
	FILE *fp;
	u_int32_t aikBlobLen;

	blob_path = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.aik_blob", NULL);

	if (blob_path)
	{
		/* Read aik key blob from a file */
		if ((fp = fopen(blob_path, "r")) == NULL)
		{
			DBG1(DBG_PTS, "unable to open AIK Blob file: %s", blob_path);
			return;
		}

		fseek(fp, 0, SEEK_END);
		aikBlobLen = ftell(fp);
		fseek(fp, 0L, SEEK_SET);

		this->aik_blob = chunk_alloc(aikBlobLen);
		if (fread(this->aik_blob.ptr, 1, aikBlobLen, fp))
		{
			DBG2(DBG_PTS, "loaded AIK Blob from '%s'", blob_path);
			DBG3(DBG_PTS, "AIK Blob: %B", &this->aik_blob);
		}
		else
		{
			DBG1(DBG_PTS, "unable to read AIK Blob file '%s'", blob_path);
		}
		fclose(fp);
		return;
	}
	
	DBG1(DBG_PTS, "AIK Blob is not available");
}

/**
 * Load an AIK certificate or public key
 * the certificate having precedence over the public key if both are present
 */
static void load_aik(private_pts_t *this)
{
	char *cert_path, *key_path;

	cert_path = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.aik_cert", NULL);
	key_path = lib->settings->get_str(lib->settings,
						"libimcv.plugins.imc-attestation.aik_key", NULL);

	if (cert_path)
	{
		this->aik = lib->creds->create(lib->creds, CRED_CERTIFICATE,
									   CERT_X509, BUILD_FROM_FILE,
									   cert_path, BUILD_END);
		if (this->aik)
		{
			DBG2(DBG_PTS, "loaded AIK certificate from '%s'", cert_path);
			return;
		}
	}
	if (key_path)
	{
		this->aik = lib->creds->create(lib->creds, CRED_CERTIFICATE,
									   CERT_TRUSTED_PUBKEY, BUILD_FROM_FILE,
									   key_path, BUILD_END);
		if (this->aik)
		{
			DBG2(DBG_PTS, "loaded AIK public key from '%s'", key_path);
			return;
		}
	}

	DBG1(DBG_PTS, "neither AIK certificate nor public key is available");
}

METHOD(pts_t, get_aik, certificate_t*,
	private_pts_t *this)
{
	return this->aik;
}

METHOD(pts_t, set_aik, void,
	private_pts_t *this, certificate_t *aik)
{
	DESTROY_IF(this->aik);
	this->aik = aik->get_ref(aik);
}

METHOD(pts_t, hash_file, bool,
	private_pts_t *this, hasher_t *hasher, char *pathname, u_char *hash)
{
	u_char buffer[PTS_BUF_SIZE];
	FILE *file;
	int bytes_read;

	file = fopen(pathname, "rb");
	if (!file)
	{
		DBG1(DBG_PTS,"  file '%s' can not be opened, %s", pathname,
			 strerror(errno));
		return FALSE;
	}
	while (TRUE)
	{
		bytes_read = fread(buffer, 1, sizeof(buffer), file);
		if (bytes_read > 0)
		{
			hasher->get_hash(hasher, chunk_create(buffer, bytes_read), NULL);
		}
		else
		{
			hasher->get_hash(hasher, chunk_empty, hash);
			break;
		}
	}
	fclose(file);

	return TRUE;
}

/**
 * Get the relative filename of a fully qualified file pathname
 */
static char* get_filename(char *pathname)
{
	char *pos, *filename;

	pos = filename = pathname;
	while (pos && *(++pos) != '\0')
	{
		filename = pos;
		pos = strchr(filename, '/');
	}
	return filename;
}

METHOD(pts_t, is_path_valid, bool,
	private_pts_t *this, char *path, pts_error_code_t *error_code)
{
	struct stat st;

	*error_code = 0;

	if (!stat(path, &st))
	{
		return TRUE;
	}
	else if (errno == ENOENT || errno == ENOTDIR)
	{
		DBG1(DBG_PTS, "file/directory does not exist %s", path);
		*error_code = TCG_PTS_FILE_NOT_FOUND;
	}
	else if (errno == EFAULT)
	{
		DBG1(DBG_PTS, "bad address %s", path);
		*error_code = TCG_PTS_INVALID_PATH;
	}
	else
	{
		DBG1(DBG_PTS, "error: %s occured while validating path: %s",
			 		   strerror(errno), path);
		return FALSE;
	}

	return TRUE;
}

METHOD(pts_t, do_measurements, pts_file_meas_t*,
	private_pts_t *this, u_int16_t request_id, char *pathname, bool is_directory)
{
	hasher_t *hasher;
	hash_algorithm_t hash_alg;
	u_char hash[HASH_SIZE_SHA384];
	chunk_t measurement;
	pts_file_meas_t *measurements;

	/* Create a hasher */
	hash_alg = pts_meas_algo_to_hash(this->algorithm);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
	if (!hasher)
	{
		DBG1(DBG_PTS, "hasher %N not available", hash_algorithm_names, hash_alg);
		return NULL;
	}

	/* Create a measurement object */
	measurements = pts_file_meas_create(request_id);

	/* Link the hash to the measurement and set the measurement length */
	measurement = chunk_create(hash, hasher->get_hash_size(hasher));

	if (is_directory)
	{
		enumerator_t *enumerator;
		char *rel_name, *abs_name;
		struct stat st;

		enumerator = enumerator_create_directory(pathname);
		if (!enumerator)
		{
			DBG1(DBG_PTS,"  directory '%s' can not be opened, %s", pathname,
				 strerror(errno));
			hasher->destroy(hasher);
			measurements->destroy(measurements);
			return NULL;
		}
		while (enumerator->enumerate(enumerator, &rel_name, &abs_name, &st))
		{
			/* measure regular files only */
			if (S_ISREG(st.st_mode) && *rel_name != '.')
			{
				if (!hash_file(this, hasher, abs_name, hash))
				{
					enumerator->destroy(enumerator);
					hasher->destroy(hasher);
					measurements->destroy(measurements);
					return NULL;
				}
				DBG2(DBG_PTS, "  %#B for '%s'", &measurement, rel_name);
				measurements->add(measurements, rel_name, measurement);
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		char *filename;

		if (!hash_file(this, hasher, pathname, hash))
		{
			hasher->destroy(hasher);
			measurements->destroy(measurements);
			return NULL;
		}
		filename = get_filename(pathname);
		DBG2(DBG_PTS, "  %#B for '%s'", &measurement, filename);
		measurements->add(measurements, filename, measurement);
	}
	hasher->destroy(hasher);

	return measurements;
}

/**
 * Obtain statistical information describing a file
 */
static bool file_metadata(char *pathname, pts_file_metadata_t **entry)
{
	struct stat st;
	pts_file_metadata_t *tmp;

	tmp = malloc_thing(pts_file_metadata_t);

	if (stat(pathname, &st))
	{
		DBG1(DBG_PTS, "Unable to obtain statistical information about %s",
			 pathname);
		return FALSE;
	}

	tmp->filename = strdup(pathname);
	tmp->meta_length = PTS_FILE_METADATA_SIZE + strlen(tmp->filename);

	if (S_ISREG(st.st_mode))
	{
		tmp->type = PTS_FILE_REGULAR;
	}
	else if (S_ISDIR(st.st_mode))
	{
		tmp->type = PTS_FILE_DIRECTORY;
	}
	else if (S_ISCHR(st.st_mode))
	{
		tmp->type = PTS_FILE_CHAR_SPEC;
	}
	else if (S_ISBLK(st.st_mode))
	{
		tmp->type = PTS_FILE_BLOCK_SPEC;
	}
	else if (S_ISFIFO(st.st_mode))
	{
		tmp->type = PTS_FILE_FIFO;
	}
	else if (S_ISLNK(st.st_mode))
	{
		tmp->type = PTS_FILE_SYM_LINK;
	}
	else if (S_ISSOCK(st.st_mode))
	{
		tmp->type = PTS_FILE_SOCKET;
	}
	else
	{
		tmp->type = PTS_FILE_OTHER;
	}

	tmp->filesize = (u_int64_t)st.st_size;
	tmp->create_time = st.st_ctime;
	tmp->last_modify_time = st.st_mtime;
	tmp->last_access_time = st.st_atime;
	tmp->owner_id = (u_int64_t)st.st_uid;
	tmp->group_id = (u_int64_t)st.st_gid;

	*entry = tmp;

	return TRUE;
}

METHOD(pts_t, get_metadata, pts_file_meta_t*,
	private_pts_t *this, char *pathname, bool is_directory)
{
	pts_file_meta_t *metadata;
	pts_file_metadata_t *entry;

	/* Create a metadata object */
	metadata = pts_file_meta_create();

	if (is_directory)
	{
		enumerator_t *enumerator;
		char *rel_name, *abs_name;
		struct stat st;

		enumerator = enumerator_create_directory(pathname);
		if (!enumerator)
		{
			DBG1(DBG_PTS,"  directory '%s' can not be opened, %s", pathname,
				 strerror(errno));
			metadata->destroy(metadata);
			return NULL;
		}
		while (enumerator->enumerate(enumerator, &rel_name, &abs_name, &st))
		{
			/* measure regular files only */
			if (S_ISREG(st.st_mode) && *rel_name != '.')
			{
				if (!file_metadata(abs_name, &entry))
				{
					enumerator->destroy(enumerator);
					metadata->destroy(metadata);
					return NULL;
				}
				metadata->add(metadata, entry);
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		char *filename;

		if (!file_metadata(pathname, &entry))
		{
			metadata->destroy(metadata);
			return NULL;
		}
		filename = get_filename(pathname);
		metadata->add(metadata, entry);
	}

	return metadata;
}

METHOD(pts_t, read_pcr, bool,
	private_pts_t *this, u_int32_t pcr_num, chunk_t *output)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	u_int32_t pcr_length;
	chunk_t pcr_value;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x",
			 result);
		return FALSE;
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
	pcr_value = chunk_alloc(PCR_LEN);
	result = Tspi_TPM_PcrRead(hTPM, pcr_num, &pcr_length, &pcr_value.ptr);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	
	*output = pcr_value;
	*output = chunk_clone(*output);

	chunk_clear(&pcr_value);
	Tspi_Context_Close(hContext);
	DBG3(DBG_PTS, "PCR %d value:%B", pcr_num, output);
	return TRUE;

	err:
	chunk_clear(&pcr_value);
	DBG1(DBG_PTS, "TPM not available: tss error 0x%x", result);
	Tspi_Context_Close(hContext);
	return FALSE;
}

METHOD(pts_t, extend_pcr, bool,
	private_pts_t *this, u_int32_t pcr_num, chunk_t input, chunk_t *output)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	u_int32_t pcr_length;
	chunk_t pcr_value;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x",
			 result);
		return FALSE;
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

	pcr_value = chunk_alloc(PCR_LEN);
	result = Tspi_TPM_PcrExtend(hTPM, pcr_num, PCR_LEN, input.ptr,
								NULL, &pcr_length, &pcr_value.ptr);
	if (result != TSS_SUCCESS)
	{
		goto err;
	}

	*output = pcr_value;
	*output = chunk_clone(*output);

	chunk_clear(&pcr_value);
	Tspi_Context_Close(hContext);
	DBG3(DBG_PTS, "PCR %d extended with:      %B", pcr_num, &input);
	DBG3(DBG_PTS, "PCR %d value after extend: %B", pcr_num, output);
	return TRUE;

	err:
	chunk_clear(&pcr_value);
	DBG1(DBG_PTS, "TPM not available: tss error 0x%x", result);
	Tspi_Context_Close(hContext);
	return FALSE;
}

METHOD(pts_t, quote_tpm, bool,
	private_pts_t *this, u_int32_t *pcrs, u_int32_t num_of_pcrs,
	chunk_t *pcr_composite, chunk_t *quote_signature)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_HKEY hAIK;
	TSS_HKEY hSRK;
	TSS_HPOLICY srkUsagePolicy;
	TSS_UUID SRK_UUID = TSS_UUID_SRK;
	BYTE secret[] = TSS_WELL_KNOWN_SECRET;
	TSS_HPCRS hPcrComposite;
	TSS_VALIDATION valData;
	u_int32_t i;
	TSS_RESULT result;
	chunk_t pcr_comp, quote_sign;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x",
			 result);
		return FALSE;
	}
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}

	/* Retrieve SRK from TPM and set the authentication to well known secret*/
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
									SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_SHA1,
					20, secret);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}
	
	result = Tspi_Context_LoadKeyByBlob (hContext, hSRK, this->aik_blob.len,
										 this->aik_blob.ptr, &hAIK);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}

	/* Create PCR composite object */
	result = Tspi_Context_CreateObject(hContext,
									   TSS_OBJECT_TYPE_PCRS, 0, &hPcrComposite);
	if (result != TSS_SUCCESS)
	{
		goto err2;
	}

	/* Select PCR's */
	for (i = 0; i < num_of_pcrs ; i++)
	{
		if (pcrs[i] < 0 || pcrs[i] >= MAX_NUM_PCR )
		{
			DBG1(DBG_PTS, "Invalid PCR number: %d", pcrs[i]);
			goto err3;
		}
		result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, pcrs[i]);
		if (result != TSS_SUCCESS)
		{
			goto err3;
		}
	}

	/* Set the Validation Data */
	valData.ulExternalDataLength = this->secret.len;
	valData.rgbExternalData = (BYTE *)this->secret.ptr;

	
	/* TPM Quote */
	result = Tspi_TPM_Quote(hTPM, hAIK, hPcrComposite, &valData);
	if (result != TSS_SUCCESS)
	{
		goto err4;
	}

	/* Set output chunks */
	pcr_comp = chunk_alloc(HASH_SIZE_SHA1);
	memcpy(pcr_comp.ptr, valData.rgbData + 8, HASH_SIZE_SHA1);
	*pcr_composite = pcr_comp;
	*pcr_composite = chunk_clone(*pcr_composite);
	DBG3(DBG_PTS, "Hash of PCR Composite: %B",pcr_composite);
	
	quote_sign = chunk_alloc(valData.ulValidationDataLength);
	memcpy(quote_sign.ptr, valData.rgbValidationData,
							  valData.ulValidationDataLength);
	*quote_signature = quote_sign;
	*quote_signature = chunk_clone(*quote_signature);
	DBG3(DBG_PTS, "TOM Quote Signature: %B",quote_signature);

	chunk_clear(&quote_sign);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hPcrComposite);
	Tspi_Context_CloseObject(hContext, hAIK);
	Tspi_Context_Close(hContext);
	free(pcrs);
	return TRUE;

	/* Cleanup */
	err4:
	Tspi_Context_FreeMemory(hContext, NULL);

	err3:
	Tspi_Context_CloseObject(hContext, hPcrComposite);

	err2:
	Tspi_Context_CloseObject(hContext, hAIK);
	
	err1:
	Tspi_Context_Close(hContext);
	free(pcrs);
	DBG1(DBG_PTS, "TPM not available: tss error 0x%x", result);
	return FALSE;
}

/**
 * Comparison function for pcr_entry_t struct
 */
static int pcr_entry_compare(const pcr_entry_t *a, const pcr_entry_t *b)
{
	return (a->pcr_number - b->pcr_number);
}

static int pcr_entry_compare_qsort(const void *a, const void *b)
{
	return pcr_entry_compare(*(const pcr_entry_t *const *)a
							, *(const pcr_entry_t *const *)b);
}

METHOD(pts_t, add_pcr_entry, void,
	private_pts_t *this, pcr_entry_t *new)
{
	enumerator_t *e;
	pcr_entry_t *entry;
	
	if (!this->pcrs)
	{
		this->pcrs = linked_list_create();
	}

	e = this->pcrs->create_enumerator(this->pcrs);
	while (e->enumerate(e, &entry))
	{
		if (entry->pcr_number == new->pcr_number)
		{
			DBG4(DBG_PTS, "updating already added PCR%d value",
				 entry->pcr_number);
			this->pcrs->remove_at(this->pcrs, e);
			free(entry);
			break;
		}
	}
	DESTROY_IF(e);
	
	this->pcrs->insert_last(this->pcrs, new);

	qsort(this->pcrs, this->pcrs->get_count(this->pcrs),
		  sizeof(pcr_entry_t *), pcr_entry_compare_qsort);
}

/**
 * 1. build a TCPA_PCR_COMPOSITE structure which contains (pcrCompositeBuf)
 * TCPA_PCR_SELECTION structure (bitmask length + bitmask)
 * UINT32 (network order) gives the number of bytes following (pcr entries * 20)
 * TCPA_PCRVALUE[] with the pcr values
 *
 * The first two bytes of the message represent the length
 * of the bitmask that follows. The bitmask represents the
 * requested PCRs to be quoted.
 *
 * TPM Main-Part 2 TPM Structures_v1.2 8.1
 * The bitmask is in big endian order"
 *
 *        BYTE 1             BYTE 2                   ...
 * Bit:   1 1 1 1 0 0 0 0    1  1  1  1  0  0  0 0    ...
 * Pcr:   7 6 5 4 3 2 1 0    15 14 13 12 11 10 9 8    ...
 *
 * 2. SHA1(pcrCompositeBuf)
 *
 * 3. build a TCPA_QUOTE_INFO structure which contains
 *	4 bytes of version
 *	4 bytes 'Q' 'U' 'O' 'T'
 *	20 byte SHA1 of TCPA_PCR_COMPOSITE
 *	20 byte nonce
 */

METHOD(pts_t, get_quote_info, bool,
	private_pts_t *this, chunk_t *out_pcr_composite, chunk_t *out_quote_info)
{
	enumerator_t *e;
	pcr_entry_t *pcr_entry;
	chunk_t pcr_composite;
	u_int32_t pcr_composite_len;
	bio_writer_t *writer;
	u_int8_t mask_bytes[PCR_MASK_LEN] = {0,0,0}, i;
	hasher_t *hasher;

	if (this->pcrs->get_count(this->pcrs) == 0)
	{
		DBG1(DBG_PTS, "PCR entries unavailable, unable to construct "
					  "TPM Quote Info");
		return FALSE;
	}

	pcr_composite_len = 2 + PCR_MASK_LEN + 4 +
						this->pcrs->get_count(this->pcrs) * PCR_LEN;

	writer = bio_writer_create(pcr_composite_len);
	/* Lenght of the bist mask field */
	writer->write_uint16(writer, PCR_MASK_LEN);
	/* Bit mask indicating selected PCRs */
	e = this->pcrs->create_enumerator(this->pcrs);
	while (e->enumerate(e, &pcr_entry))
	{
		u_int32_t index = pcr_entry->pcr_number;
		mask_bytes[index / 8] |= (1 << (index % 8));
	}
	e->destroy(e);

	for (i = 0; i< PCR_MASK_LEN ; i++)
	{
		writer->write_uint8(writer, mask_bytes[i]);
	}

	/* Lenght of the pcr entries */
	writer->write_uint32(writer, this->pcrs->get_count(this->pcrs) * PCR_LEN);
	/* Actual PCR values */
	e = this->pcrs->create_enumerator(this->pcrs);
	while (e->enumerate(e, &pcr_entry))
	{
		writer->write_data(writer, chunk_create(pcr_entry->pcr_value, PCR_LEN));
	}
	free(pcr_entry);
	e->destroy(e);
	
	/* PCR Composite structure */
	pcr_composite = chunk_clone(writer->get_buf(writer));
	writer->destroy(writer);

	writer = bio_writer_create(TPM_QUOTE_INFO_LEN);
	/* Version number */
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 1);
	writer->write_uint8(writer, 0);
	writer->write_uint8(writer, 0);

	/* Magic QUOT value, depends on TPM Ordinal */
	writer->write_uint8(writer, 'Q');
	writer->write_uint8(writer, 'U');
	writer->write_uint8(writer, 'O');
	writer->write_uint8(writer, 'T');

	/* SHA1 hash of PCR Composite Structure */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	hasher->allocate_hash(hasher, pcr_composite, out_pcr_composite);
	DBG4(DBG_PTS, "Hash of calculated PCR Composite: %B", out_pcr_composite);

	chunk_clear(&pcr_composite);
	hasher->destroy(hasher);
	writer->write_data(writer, *out_pcr_composite);
	
	if (!this->secret.ptr)
	{
		DBG1(DBG_PTS, "Secret assessment value unavailable",
			 "unable to construct TPM Quote Info");
		chunk_clear(out_pcr_composite);
		writer->destroy(writer);
		return FALSE;
	}
	/* Secret assessment value 20 bytes (nonce) */
	writer->write_data(writer, this->secret);
	/* TPM Quote Info */
	*out_quote_info = chunk_clone(writer->get_buf(writer));
	DBG4(DBG_PTS, "Calculated TPM Quote Info: %B", out_quote_info);
	writer->destroy(writer);
	
	return TRUE;
}

METHOD(pts_t, verify_quote_signature, bool,
				private_pts_t *this, chunk_t data, chunk_t signature)
{
	public_key_t *aik_pub_key;
	chunk_t key_encoding;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	unsigned char *p;

	aik_pub_key = this->aik->get_public_key(this->aik);
	if (!aik_pub_key)
	{
		DBG1(DBG_PTS, "failed to get public key from AIK certificate");
		return FALSE;
	}

	/** Implementation using strongswan -> not working */
	/**if (!aik_pub_key->verify(aik_pub_key, SIGN_RSA_EMSA_PKCS1_SHA1,
															data, signature))
	{
		DBG1(DBG_PTS, "signature verification failed for TPM Quote Info");
		goto cleanup;
	}
	*/

	if (!aik_pub_key->get_encoding(aik_pub_key,
		PUBKEY_SPKI_ASN1_DER, &key_encoding))
	{
		DBG1(DBG_PTS, "failed to get encoding of AIK public key");
		goto cleanup;
	}
	
	p = key_encoding.ptr;
	pkey = d2i_PUBKEY(NULL, (const unsigned char**)&p, key_encoding.len);
	if (!pkey)
	{
		DBG1(DBG_PTS, "failed to get EVP_PKEY object from AIK public key");
		goto cleanup;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
	{
		DBG1(DBG_PTS, "failed to get RSA object from EVP_PKEY");
		goto cleanup;
	}

	if (RSA_verify(NID_sha1, data.ptr, data.len,
		signature.ptr, signature.len, rsa) != 1)
	{
		DBG1(DBG_PTS, "signature verification failed for TPM Quote Info");
		goto cleanup;
	}

	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	if (key_encoding.ptr)
	{
		chunk_clear(&key_encoding);
	}
	aik_pub_key->destroy(aik_pub_key);
	return TRUE;

cleanup:
	if (rsa)
	{
		RSA_free(rsa);
	}
	if (pkey)
	{
		EVP_PKEY_free(pkey);
	}
	if (key_encoding.ptr)
	{
		chunk_clear(&key_encoding);
	}
	DESTROY_IF(aik_pub_key);
	return FALSE;
}

METHOD(pts_t, destroy, void,
	private_pts_t *this)
{
	DESTROY_IF(this->aik);
	DESTROY_IF(this->dh);
	DESTROY_IF(this->pcrs);
	free(this->initiator_nonce.ptr);
	free(this->responder_nonce.ptr);
	free(this->secret.ptr);
	free(this->platform_info);
	free(this->aik_blob.ptr);
	free(this->tpm_version_info.ptr);
	free(this);
}

/**
 * Determine Linux distribution and hardware platform
 */
static char* extract_platform_info(void)
{
	FILE *file;
	char buf[BUF_LEN], *pos, *value = NULL;
	int i, len;
	struct utsname uninfo;

	/* Linux/Unix distribution release info (from http://linuxmafia.com) */
	const char* releases[] = {
		"/etc/lsb-release",           "/etc/debian_version",
		"/etc/SuSE-release",          "/etc/novell-release",
		"/etc/sles-release",          "/etc/redhat-release",
		"/etc/fedora-release",        "/etc/gentoo-release",
		"/etc/slackware-version",     "/etc/annvix-release",
		"/etc/arch-release",          "/etc/arklinux-release",
		"/etc/aurox-release",         "/etc/blackcat-release",
		"/etc/cobalt-release",        "/etc/conectiva-release",
		"/etc/debian_release",        "/etc/immunix-release",
		"/etc/lfs-release",           "/etc/linuxppc-release",
		"/etc/mandrake-release",      "/etc/mandriva-release",
		"/etc/mandrakelinux-release", "/etc/mklinux-release",
		"/etc/pld-release",           "/etc/redhat_version",
		"/etc/slackware-release",     "/etc/e-smith-release",
		"/etc/release",               "/etc/sun-release",
		"/etc/tinysofa-release",      "/etc/turbolinux-release",
		"/etc/ultrapenguin-release",  "/etc/UnitedLinux-release",
		"/etc/va-release",            "/etc/yellowdog-release"
	};

	const char description[] = "DISTRIB_DESCRIPTION=\"";

	for (i = 0; i < countof(releases); i++)
	{
		file = fopen(releases[i], "r");
		if (!file)
		{
			continue;
		}
		fseek(file, 0, SEEK_END);
		len = min(ftell(file), sizeof(buf)-1);
		rewind(file);
		buf[len] = '\0';
		if (fread(buf, 1, len, file) != len)
		{
			DBG1(DBG_PTS, "failed to read file '%s'", releases[i]);
			fclose(file);
			return NULL;
		}
		fclose(file);

		if (i == 0) /* LSB release */
		{
			pos = strstr(buf, description);
			if (!pos)
			{
				DBG1(DBG_PTS, "failed to find begin of lsb-release "
							  "DESCRIPTION field");
				return NULL;
			}
			value = pos + strlen(description);
			pos = strchr(value, '"');
			if (!pos)
			{
				DBG1(DBG_PTS, "failed to find end of lsb-release "
							  "DESCRIPTION field");
				return NULL;
			 }
		}
		else
		{
			value = buf;
			pos = strchr(value, '\n');
			if (!pos)
			{
				DBG1(DBG_PTS, "failed to find end of release string");
				return NULL;
			 }
		}
		break;
	}

	if (!value)
	{
		DBG1(DBG_PTS, "no distribution release file found");
		return NULL;
	}

	if (uname(&uninfo) < 0)
	{
		DBG1(DBG_PTS, "could not retrieve machine architecture");
		return NULL;
	}

	*pos++ = ' ';
	len = sizeof(buf)-1 + (pos - buf);
	strncpy(pos, uninfo.machine, len);

	DBG1(DBG_PTS, "platform is '%s'", value);
	return strdup(value);
}

/**
 * Check for a TPM by querying for TPM Version Info
 */
static bool has_tpm(private_pts_t *this)
{
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	u_int32_t version_info_len;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x",
			 result);
		return FALSE;
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
									&version_info_len,
									&this->tpm_version_info.ptr);
	this->tpm_version_info.len = version_info_len;
	if (result != TSS_SUCCESS)
	{
		goto err;
	}
	this->tpm_version_info = chunk_clone(this->tpm_version_info);
	Tspi_Context_Close(hContext);
	return TRUE;

	err:
	DBG1(DBG_PTS, "TPM not available: tss error 0x%x", result);
	Tspi_Context_Close(hContext);
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
			.get_dh_hash_algorithm = _get_dh_hash_algorithm,
			.set_dh_hash_algorithm = _set_dh_hash_algorithm,
			.create_dh_nonce = _create_dh_nonce,
			.get_my_public_value = _get_my_public_value,
			.set_peer_public_value = _set_peer_public_value,
			.calculate_secret = _calculate_secret,
			.get_platform_info = _get_platform_info,
			.set_platform_info = _set_platform_info,
			.get_tpm_version_info = _get_tpm_version_info,
			.set_tpm_version_info = _set_tpm_version_info,
			.get_aik = _get_aik,
			.set_aik = _set_aik,
			.is_path_valid = _is_path_valid,
			.hash_file = _hash_file,
			.do_measurements = _do_measurements,
			.get_metadata = _get_metadata,
			.read_pcr = _read_pcr,
			.extend_pcr = _extend_pcr,
			.quote_tpm = _quote_tpm,
			.add_pcr_entry = _add_pcr_entry,
			.get_quote_info = _get_quote_info,
			.verify_quote_signature  = _verify_quote_signature,
			.destroy = _destroy,
		},
		.is_imc = is_imc,
		.proto_caps = PTS_PROTO_CAPS_V,
		.algorithm = PTS_MEAS_ALGO_SHA256,
		.dh_hash_algorithm = PTS_MEAS_ALGO_SHA256,
	);

	if (is_imc)
	{
		this->platform_info = extract_platform_info();

		if (has_tpm(this))
		{
			this->has_tpm = TRUE;
			this->proto_caps |= PTS_PROTO_CAPS_T;
			load_aik(this);
			load_aik_blob(this);
		}
	}
	else
	{
		this->proto_caps |= PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_C;
	}

	return &this->public;
}
