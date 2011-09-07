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
#include <utils/lexparser.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

#include <sys/stat.h>
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
	DBG2(DBG_IMC, "supported PTS protocol capabilities: %s%s%s%s%s",
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
	DBG2(DBG_IMC, "selected PTS measurement algorithm is %N",
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
			DBG2(DBG_IMC, "loaded AIK certificate from '%s'", cert_path);
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
			DBG2(DBG_IMC, "loaded AIK public key from '%s'", key_path);
			return;
		}
	}
	DBG1(DBG_IMC, "neither AIK certificate nor public key is available");
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

/**
 * Compute a hash over a file
 */
static bool hash_file(hasher_t *hasher, char *pathname, u_char *hash)
{
	u_char buffer[PTS_BUF_SIZE];
	FILE *file;
	int bytes_read;

	file = fopen(pathname, "rb");
	if (!file)
	{
		DBG1(DBG_IMC,"  file '%s' can not be opened, %s", pathname,
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
		DBG1(DBG_IMC, "  hasher %N not available", hash_algorithm_names, hash_alg);
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
			DBG1(DBG_IMC,"  directory '%s' can not be opened, %s", pathname,
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
				if (!hash_file(hasher, abs_name, hash))
				{
					enumerator->destroy(enumerator);
					hasher->destroy(hasher);
					measurements->destroy(measurements);
					return NULL;
				}
				DBG2(DBG_IMC, "  %#B for '%s'", &measurement, rel_name);
				measurements->add(measurements, rel_name, measurement);
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		char *filename;

		if (!hash_file(hasher, pathname, hash))
		{
			hasher->destroy(hasher);
			measurements->destroy(measurements);
			return NULL;
		}
		filename = get_filename(pathname);
		DBG2(DBG_IMC, "  %#B for '%s'", &measurement, filename);
		measurements->add(measurements, filename, measurement);
	}
	hasher->destroy(hasher);

	return measurements;
}

METHOD(pts_t, destroy, void,
	   private_pts_t *this)
{
	DESTROY_IF(this->aik);
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
	const char description[] = "Description:";
	char buf[BUF_LEN], *pos, *value;
	int value_len;

	/* open a pipe stream for reading the output of the lsb_release commmand */
	file = popen("/usr/bin/lsb_release -d" , "r");
	if (!file)
	{
		DBG2(DBG_IMC, "failed to run lsb_release command");
		return NULL;
	}

	/* read the output the lsb_release command */
	if (!fgets(buf, BUF_LEN-1, file))
	{
		DBG2(DBG_IMC, "failed to read output of lsb_release command");
		pclose(file);
		return NULL;
	}
	pclose(file);

	pos = strstr(buf, description);
	if (!pos)
	{
		DBG2(DBG_IMC, "failed to find lsb_release description field");
		return NULL;
	}
	value = pos + strlen(description);

	/* eat whitespace */
	while (*value == ' ' || *value == '\t')
	{
		value++;
	}

	/* remove newline at the end and move value to the front of the buffer */
	value_len = strlen(value) - 1;
	memcpy(buf, value, value_len);
	buf[value_len] = ' ';

 	/* open a pipe stream for reading the output of the uname commmand */
	file = popen("/bin/uname -p" , "r");
	if (!file)
	{
		DBG2(DBG_IMC, "failed to run uname command");
		return NULL;
	}
		
	/* Read the output the uname command */
	if (!fgets(buf + value_len + 1, BUF_LEN - value_len - 2, file))
	{
		DBG2(DBG_IMC, "failed to read output of uname command");
		pclose(file);
		return NULL;
	}
	pclose(file);

	/* remove newline at the end */
	buf[strlen(buf)-1] = '\0';

	DBG1(DBG_IMV, "platform is '%s'", buf);
	return strdup(buf);	
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
	DBG1(DBG_IMC, "TPM not available: tss error 0x%x", result);
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
			 .get_platform_info = _get_platform_info,
			 .set_platform_info = _set_platform_info,
			 .get_tpm_version_info = _get_tpm_version_info,
			 .set_tpm_version_info = _set_tpm_version_info,
			 .get_aik = _get_aik,
			 .set_aik = _set_aik,
			 .do_measurements = _do_measurements,
			 .destroy = _destroy,
		 },
		 .proto_caps = PTS_PROTO_CAPS_V,
		 .algorithm = PTS_MEAS_ALGO_SHA256,
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

