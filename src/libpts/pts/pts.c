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

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>

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
	 * PTS Diffie Hellman Group
	 */
	pts_dh_group_t dh_group;

	/**
	 * Contains a Diffie Hellman object
	 */
	diffie_hellman_t *dh;

	/**
	 * Secret assessment value to be used for TPM Quote as an external data
	 */
	chunk_t secret;

	/**
	 * Platform and OS Info
	 */
	char *platform_info;

	/**
	 * Do we have an activated TPM
	 */
	bool has_tpm;

	/**
	 * Contains a TPM_CAP_VERSION_INFO struct
	 */
	chunk_t tpm_version_info;

	/**
	 * Contains a Attestation Identity Key or Certificate
	 */
 	certificate_t *aik;

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

	hash_alg = pts_meas_to_hash_algorithm(algorithm);
	DBG2(DBG_PTS, "selected PTS measurement algorithm is %N",
		 hash_algorithm_names, hash_alg);
	if (hash_alg != HASH_UNKNOWN)
	{
		this->algorithm = algorithm;
	}
}

METHOD(pts_t, get_dh_group, pts_dh_group_t,
	   private_pts_t *this)
{
	return this->dh_group;
}

METHOD(pts_t, set_dh_group, void,
	   private_pts_t *this, pts_dh_group_t group)
{
	diffie_hellman_group_t dh_group;

	dh_group = pts_dh_group_to_strongswan_dh_group(group);
	DBG2(DBG_PTS, "selected PTS Diffie Hellman Group is %N",
		 diffie_hellman_group_names, dh_group);
	if (dh_group != MODP_NONE)
	{
		this->dh_group = group;
	}
}

METHOD(pts_t, create_dh, bool,
	   private_pts_t *this, pts_dh_group_t group)
{
	diffie_hellman_group_t dh_group;

	dh_group = pts_dh_group_to_strongswan_dh_group(group);
	if (dh_group != MODP_NONE)
	{
		this->dh = lib->crypto->create_dh(lib->crypto, dh_group);
		return TRUE;
	}
	DBG1(DBG_PTS, "Unable to create Diffie Hellman object with group %N",
		diffie_hellman_group_names, dh_group);
	return FALSE;
}

METHOD(pts_t, get_my_pub_val, void,
	   private_pts_t *this, chunk_t *pub_value)
{
	this->dh->get_my_public_value(this->dh, pub_value);
	DBG3(DBG_PTS, "My Public value:%B", pub_value);
}

METHOD(pts_t, set_other_pub_val, void,
	   private_pts_t *this, chunk_t value)
{
	DBG3(DBG_PTS, "Partner's Public value:%B", &value);
	this->dh->set_other_public_value(this->dh, value);
}

METHOD(pts_t, calculate_secret, bool,
	   private_pts_t *this, chunk_t initiator_nonce, chunk_t responder_nonce,
	   pts_meas_algorithms_t algorithm)
{
	hasher_t *hasher;
	hash_algorithm_t hash_alg;
	u_char output[HASH_SIZE_SHA384];
	chunk_t shared_secret;

	/* Create a hasher */
	hash_alg = pts_meas_to_hash_algorithm(algorithm);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
	if (!hasher)
	{
		DBG1(DBG_PTS, "  hasher %N not available", hash_algorithm_names, hash_alg);
		return FALSE;
	}

	if (this->dh->get_shared_secret(this->dh, &shared_secret) != SUCCESS)
	{
		DBG1(DBG_PTS, "Shared secret couldn't be calculated");
		hasher->destroy(hasher);
		return FALSE;
	}

	hasher->get_hash(hasher, chunk_create("1", sizeof("1")), NULL);
	hasher->get_hash(hasher, initiator_nonce, NULL);
	hasher->get_hash(hasher, responder_nonce, NULL);
	hasher->get_hash(hasher, shared_secret, output);

	/**
	 * Link the hash output to the secret and set the length
	 * Truncate the output to 20 bytes to fit ExternalDate argument of TPM Quote
	 */
	this->secret = chunk_create(output, HASH_SIZE_SHA1);
	DBG3(DBG_PTS, "Secret assessment value: %B", &this->secret);

	chunk_free(&shared_secret);
	hasher->destroy(hasher);
	return TRUE;
}

METHOD(pts_t, get_secret, chunk_t,
	   private_pts_t *this)
{
	return this->secret;
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
 * Load an AIK certificate or public key,
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

METHOD(pts_t, is_path_valid, bool, private_pts_t *this, char *path,
						pts_error_code_t *error_code)
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
	hash_alg = pts_meas_to_hash_algorithm(this->algorithm);
	hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
	if (!hasher)
	{
		DBG1(DBG_PTS, "  hasher %N not available", hash_algorithm_names, hash_alg);
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
		DBG1(DBG_PTS, "Unable to obtain statistical information about %s", pathname);
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
				DBG3(DBG_PTS, "File name:          %s", entry->filename);
				DBG3(DBG_PTS, "     type:          %d", entry->type);
				DBG3(DBG_PTS, "     size:          %d", entry->filesize);
				DBG3(DBG_PTS, "     create time:   %s", ctime(&entry->create_time));
				DBG3(DBG_PTS, "     last modified: %s", ctime(&entry->last_modify_time));
				DBG3(DBG_PTS, "     last accessed: %s", ctime(&entry->last_access_time));
				DBG3(DBG_PTS, "     owner id:      %d", entry->owner_id);
				DBG3(DBG_PTS, "     group id:      %d", entry->group_id);

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
		DBG3(DBG_PTS, "File name:          %s", entry->filename);
		DBG3(DBG_PTS, "     type:          %d", entry->type);
		DBG3(DBG_PTS, "     size:          %d", entry->filesize);
		DBG3(DBG_PTS, "     create time:   %s", ctime(&entry->create_time));
		DBG3(DBG_PTS, "     last modified: %s", ctime(&entry->last_modify_time));
		DBG3(DBG_PTS, "     last accessed: %s", ctime(&entry->last_access_time));
		DBG3(DBG_PTS, "     owner id:      %d", entry->owner_id);
		DBG3(DBG_PTS, "     group id:      %d", entry->group_id);
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
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x", result);
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
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x", result);
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
	   private_pts_t *this, linked_list_t *pcrs,
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
	TPM_QUOTE_INFO *quoteInfo;
	u_int32_t i, pcr;
	TSS_RESULT result;
	chunk_t aik_key_encoding;
	chunk_t pcr_composite_without_nonce;
	enumerator_t *enumerator;

	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x", result);
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

	/* Retrieve SRK from TPM and set the authentication data as well known secret*/
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

	/* Create from AIK public key a HKEY object to sign Quote operation output*/
	if (this->aik->get_type(this->aik) == CERT_TRUSTED_PUBKEY)
	{
		if (!this->aik->get_encoding(this->aik, CERT_ASN1_DER, &aik_key_encoding))
		{
			DBG1(DBG_PTS, "encoding AIK certificate for quote operation failed");
			goto err1;
		}
	}
	else if (this->aik->get_type(this->aik) == CERT_X509)
	{
		public_key_t *key = this->aik->get_public_key(this->aik);

		if (key == NULL)
		{
			DBG1(DBG_PTS, "unable to retrieve public key from AIK certificate");
			goto err1;
		}
		if (!key->get_encoding(key, PUBKEY_ASN1_DER, &aik_key_encoding))
		{
			DBG1(DBG_PTS, "encoding AIK Public Key for quote operation failed");
			goto err1;
		}
	}
	else
	{
		DBG1(DBG_PTS, "AIK is neither X509 certificate nor Public Key");
		goto err1;
	}

	result = Tspi_Context_LoadKeyByBlob (hContext, hSRK, aik_key_encoding.len,
										 (BYTE*)aik_key_encoding.ptr, &hAIK);
	if (result != TSS_SUCCESS)
	{
		goto err1;
	}

	/* Create PCR composite object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPcrComposite);
	if (result != TSS_SUCCESS)
	{
		goto err2;
	}

	/* Select PCR's */
	enumerator = pcrs->create_enumerator(pcrs);
	while (enumerator->enumerate(enumerator, &pcr))
	{
		if (pcr < 0 || pcr >= MAX_NUM_PCR )
		{
			DBG1(DBG_PTS, "Invalid PCR number: %d", pcr);
			goto err3;
		}
		result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, pcr);
		if (result != TSS_SUCCESS)
		{
			goto err3;
		}
	}
	enumerator->destroy(enumerator);

	/* Set the Validation Data */
	valData.ulExternalDataLength = this->secret.len;
	valData.rgbExternalData = (BYTE *)this->secret.ptr;

	/* TPM Quote */
	result = Tspi_TPM_Quote(hTPM, hAIK, hPcrComposite, &valData);
	if (result != TSS_SUCCESS)
	{
		goto err4;
	}

	quoteInfo = (TPM_QUOTE_INFO *)valData.rgbData;

	/* Display quote info */
	DBG3(DBG_PTS, "version:");
	for(i = 0 ; i < 4 ; i++)
	{
		DBG3(DBG_PTS, "%02x ",valData.rgbData[i]);
	}
	DBG3(DBG_PTS, "fixed value:");
	for(i = 4 ; i < 8 ; i++)
	{
		DBG3(DBG_PTS, "%c",valData.rgbData[i]);
	}
	DBG3(DBG_PTS, "pcr digest:");
	for(i = 8 ; i < 28 ; i++)
	{
		DBG3(DBG_PTS, "%02x ",valData.rgbData[i]);
	}
	DBG3(DBG_PTS, "nonce:");
	for(i = 28 ; i < valData.ulDataLength ; i++)
	{
		DBG3(DBG_PTS, "%c",valData.rgbData[i]);
	}

	/* Set output chunks */
	pcr_composite_without_nonce = chunk_alloc(
		valData.ulDataLength - ASSESSMENT_SECRET_LEN);
	memcpy(pcr_composite_without_nonce.ptr, valData.rgbData,
		   valData.ulDataLength - ASSESSMENT_SECRET_LEN);
	*pcr_composite = pcr_composite_without_nonce;
	*pcr_composite = chunk_clone(*pcr_composite);
	free(pcr_composite_without_nonce.ptr);
	
	*quote_signature = chunk_from_thing(valData.rgbValidationData);
	*quote_signature = chunk_clone(*quote_signature);
	
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hPcrComposite);
	Tspi_Context_CloseObject(hContext, hAIK);
	Tspi_Context_Close(hContext);
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
	DBG1(DBG_PTS, "TPM not available: tss error 0x%x", result);
	return FALSE;
}

METHOD(pts_t, destroy, void,
	   private_pts_t *this)
{
	DESTROY_IF(this->aik);
	DESTROY_IF(this->dh);
	free(this->platform_info);
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
		DBG1(DBG_PTS, "TPM context could not be created: tss error 0x%x", result);
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
			 .get_dh_group = _get_dh_group,
			 .set_dh_group = _set_dh_group,
			 .create_dh = _create_dh,
			 .get_my_pub_val = _get_my_pub_val,
			 .set_other_pub_val = _set_other_pub_val,
			 .calculate_secret = _calculate_secret,
			 .get_secret = _get_secret,
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
			 .destroy = _destroy,
		 },
		 .proto_caps = PTS_PROTO_CAPS_V,
		 .algorithm = PTS_MEAS_ALGO_SHA256,
		 .dh_group = PTS_DH_GROUP_IKE19,
	);

	if (is_imc)
	{
		this->platform_info = extract_platform_info();

		if (has_tpm(this))
		{
			this->has_tpm = TRUE;
			this->proto_caps |= PTS_PROTO_CAPS_T;
			load_aik(this);
		}
	}
	else
	{
		this->proto_caps |= PTS_PROTO_CAPS_T | PTS_PROTO_CAPS_C;
	}

	return &this->public;
}

