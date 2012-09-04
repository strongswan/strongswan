/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "eap_ms_soh.h"

#include <daemon.h>
#include <library.h>
#include <bio/bio_writer.h>
#include <bio/bio_reader.h>

typedef struct private_eap_ms_soh_t private_eap_ms_soh_t;
typedef enum soh_tlv_t soh_tlv_t;
typedef enum soh_health_class_t soh_health_class_t;
typedef enum soh_attribute_t soh_attribute_t;
typedef enum soh_format_t soh_format_t;
typedef enum soh_status_t soh_status_t;
typedef enum soh_update_policy_t soh_update_policy_t;
typedef enum soh_procarch_t soh_procarch_t;
typedef enum soh_type_t soh_type_t;

/**
 * SoH TLV types
 */
enum soh_tlv_t {
	SOH_SYSTEM_HEALTH_ID = 2,
	SOH_IPV4_FIXUP_SERVERS = 3,
	SOH_COMPLIANCE_RESULT_CODES = 4,
	SOH_TIME_OF_LAST_UPDATE = 5,
	SOH_CLIENT_ID = 6,
	SOH_VENDOR = 7,
	SOH_HEALTH_CLASS = 8,
	SOH_SOFTWARE_VERSION = 9,
	SOH_PRODUCT_NAME = 10,
	SOH_HEALTH_CLASS_STATUS = 11,
	SOH_GENERATION_TIME = 12,
	SOH_ERROR_CODES = 13,
	SOH_FAILURE_CATEGORY = 14,
	SOH_IPV6_FIXUP_SERVERS = 15,
};

/**
 * SoH component classes
 */
enum soh_health_class_t {
	SOH_FIREWALL = 0,
	SOH_ANTIVIRUS = 1,
	SOH_ANTISPYWARE = 2,
	SOH_AUTOMATIC_UPDATES = 3,
	SOH_SECURITY_UPDATES = 4,
};

/**
 * SSoH attributes
 */
enum soh_attribute_t {
	MS_MACHINE_INVENTORY = 1,
	MS_QUARANTINE_STATE = 2,
	MS_PACKET_INFO = 3,
	MS_SYSTEMGENERATED_IDS = 4,
	MS_MACHINENAME = 5,
	MS_CORRELATIONID = 6,
	MS_INSTALLED_SHVS = 7,
	MS_MACHINE_INVENTORY_EX = 8,
};

/**
 * SoH packet format
 */
enum soh_format_t {
	/* no sub header */
	SOH_FORMAT_DEFAULT = 1,
	/* with sub header */
	SOH_FORMAT_SUB_HEADER = 2,
};

/**
 * Health status for the different classes
 */
enum soh_status_t {
	/* updates applied, success */
	SOH_NO_MISSING_UPDATES = 0x00FF0005,
	/* different error codes */
	SOH_MISSING_UPDATES = 0x00FF0006,
	SOH_WUA_SERVICE_NOT_STARTED_SINCE_BOOT = 0x00FF0008,
	SOH_PRODUCT_NOT_INSTALLED = 0xC0FF0002,
	SOH_WSC_SERVICE_DOWN = 0xC0FF0003,
	SOH_NO_WUS_SERVER = 0xC0FF000C,
	SOH_NO_CLIENT_ID = 0xC0FF000D,
	SOH_WUA_SERVICE_DISABLED = 0xC0FF000E,
	SOH_WUA_COMM_FAILURE = 0xC0FF000F,
	SOH_UPDATES_INSTALLED_REQUIRE_REBOOT = 0xC0FF0010,
	SOH_WSC_SERVICE_NOT_STARTED_SINCE_BOOT = 0xC0FF0018,

	/* bitmask of all flags, apply only if other bits not set */
	SOH_FLAGS = 0x0F,
	SOH_ENABLED = (1<<0),
	SOH_UP_TO_DATE = (1<<1),
	SOH_MICROSOFT = (1<<2),
	SOH_SNOOZED = (1<<3),
};

/**
 * Windows Update policy
 */
enum soh_update_policy_t {
	SOH_UPDATES_DISABLED = 1,
	SOH_UPDATES_CHECK_ONLY = 2,
	SOH_UPDATES_DOWNLOAD_ONLY = 3,
	SOH_UPDATES_INSTALL = 4,
	SOH_UPDATES_NOT_CONFIGURED = 5,
	/* flag indicating that it has been set "by policy", whatever that means */
	SOH_UPDATES_BY_POLICY = 0x100,
};

/**
 * Processor architecture
 */
enum soh_procarch_t {
	SOH_PROCARCH_X86 = 0,
	SOH_PROCARCH_IA64 = 6,
	SOH_PROCARCH_X64 = 9,
};
/**
 * Vendor specific types in SOH_VENDOR for PEN_MICROSOFT
 */
enum soh_type_t {
	SOH = 1,
	SOH_REQUEST = 2,
};

/**
 * Private data of an eap_ms_soh_t object.
 */
struct private_eap_ms_soh_t {

	/**
	 * Public interface.
	 */
	eap_ms_soh_t public;

	/**
	 * Current EAP packet identifier
	 */
	u_int8_t identifier;

	/**
	 * Running Firewall?
	 */
	bool firewall;

	/**
	 * Running and up to date Antivirus
	 */
	bool antivirus;

	/**
	 * Running and up to date Antispyware
	 */
	bool antispyware;

	/**
	 * Automatic Update policy
	 */
	soh_update_policy_t update;

	/**
	 * All critical security updates applied?
	 */
	bool security_updates;
};

ENUM(soh_tlv_names, SOH_SYSTEM_HEALTH_ID, SOH_IPV6_FIXUP_SERVERS,
	"System-Health-Id",
	"IPv4-Fixup-Servers",
	"Compliance-Result-Codes",
	"Time-Of-Last-Update",
	"Client-Id",
	"Vendor",
	"Health-Class",
	"Software-Version",
	"Product-Name",
	"Health-Class-Status",
	"Generation-Time",
	"Error-Codes",
	"Failure-Category",
	"IPv6-Fixup-Servers",
);

ENUM(soh_health_class_names, SOH_FIREWALL, SOH_SECURITY_UPDATES,
	"Firewall",
	"Antivirus",
	"Antispyware",
	"Automatic Updates",
	"Security Updates",
);


ENUM(soh_attribute_names, MS_MACHINE_INVENTORY, MS_MACHINE_INVENTORY_EX,
	"MS-Machine-Inventory",
	"MS-Quarantine-State",
	"MS-Packet-Info",
	"MS-SystemGenerated-Ids",
	"MS-MachineName",
	"MS-CorrelationId",
	"MS-Installed-Shvs",
	"MS-Machine-Inventory-Ex",
);

ENUM_BEGIN(soh_status_names,
	SOH_NO_MISSING_UPDATES,
	SOH_WUA_SERVICE_NOT_STARTED_SINCE_BOOT,
	"no missing updates",
	"7",
	"missing updates",
	"Windows Update not started since boot",
);
ENUM_NEXT(soh_status_names,
	SOH_PRODUCT_NOT_INSTALLED,
	SOH_WSC_SERVICE_DOWN,
	SOH_WUA_SERVICE_NOT_STARTED_SINCE_BOOT,
	"product not installed",
	"Windows Security Center service down",
);
ENUM_NEXT(soh_status_names,
	SOH_NO_WUS_SERVER,
	SOH_UPDATES_INSTALLED_REQUIRE_REBOOT,
	SOH_WSC_SERVICE_DOWN,
	"no WSUS server",
	"no WSUS client ID",
	"Windows Update disabled",
	"Windows Update communication failure",
	"Updates installed, but reboot required",
);
ENUM_NEXT(soh_status_names,
	SOH_WSC_SERVICE_NOT_STARTED_SINCE_BOOT,
	SOH_WSC_SERVICE_NOT_STARTED_SINCE_BOOT,
	SOH_UPDATES_INSTALLED_REQUIRE_REBOOT,
	"Windows Security Center not started since boot",
);
ENUM_END(soh_status_names, SOH_WSC_SERVICE_NOT_STARTED_SINCE_BOOT);

ENUM(soh_update_policy_names,
	SOH_UPDATES_DISABLED, SOH_UPDATES_NOT_CONFIGURED,
	"disabled",
	"check only",
	"download only",
	"install automatically",
	"not configured",
);

ENUM_BEGIN(soh_procarch_names, SOH_PROCARCH_X86, SOH_PROCARCH_X86,
	"x86",
);
ENUM_NEXT(soh_procarch_names, SOH_PROCARCH_IA64, SOH_PROCARCH_IA64,
	SOH_PROCARCH_X86,
	"IA64",
);
ENUM_NEXT(soh_procarch_names, SOH_PROCARCH_X64, SOH_PROCARCH_X64,
	SOH_PROCARCH_IA64,
	"x64",
);
ENUM_END(soh_procarch_names, SOH_PROCARCH_X64);


METHOD(eap_method_t, initiate, status_t,
	private_eap_ms_soh_t *this, eap_payload_t **out)
{
	bio_writer_t *writer;

	writer = bio_writer_create(32);
	writer->write_uint8(writer, EAP_REQUEST);
	writer->write_uint8(writer, this->identifier);
	writer->write_uint16(writer, 24);
	writer->write_uint8(writer, EAP_EXPANDED);
	writer->write_uint24(writer, PEN_MICROSOFT);
	writer->write_uint32(writer, EAP_MS_SOH);
	writer->write_uint16(writer, SOH_VENDOR);
	writer->write_uint16(writer, 8);
	writer->write_uint32(writer, PEN_MICROSOFT);
	writer->write_uint16(writer, SOH_REQUEST);
	writer->write_uint16(writer, 0);

	*out = eap_payload_create_data(writer->get_buf(writer));
	writer->destroy(writer);

	return NEED_MORE;
}

/**
 * Minimalistic UTF-16 to ASCII conversion
 */
static void convert_utf16_to_ascii(chunk_t utf16, char *buf, size_t len)
{
	int pos = 0;

	while (utf16.len > 1 && pos < (len - 1))
	{
		if (utf16.ptr[1] || utf16.ptr[0] > 127)
		{
			buf[pos] = '?';
		}
		else
		{
			buf[pos] = utf16.ptr[0];
		}
		utf16 = chunk_skip(utf16, 2);
		pos++;
	}
	buf[pos] = 0;
}

/**
 * Evaluate and log a health class status
 */
static void evaluate_status(private_eap_ms_soh_t *this, soh_health_class_t class,
							char *product, soh_status_t status)
{
	if (status & ~SOH_FLAGS)
	{	/* error/status code */
		DBG1(DBG_IKE, "  %N: %s, %N",
			 soh_health_class_names, class,
			 status & SOH_MICROSOFT ? "builtin" : product,
			 soh_status_names, status);
		if (class == SOH_SECURITY_UPDATES &&
			status == SOH_NO_MISSING_UPDATES)
		{
			this->security_updates = TRUE;
		}
	}
	else
	{
		char *label = "disabled";
		bool running = FALSE;

		if (status & SOH_ENABLED)
		{
			if (status & SOH_SNOOZED)
			{
				label = "snoozed";
			}
			else
			{
				label = "enabled";
				running = TRUE;
			}
		}
		switch (class)
		{
			case SOH_AUTOMATIC_UPDATES:
				this->update = status & ~SOH_UPDATES_BY_POLICY;
				DBG1(DBG_IKE, "  %N: %N",
					 soh_health_class_names, class,
					 soh_update_policy_names, this->update);
				break;
			case SOH_FIREWALL:
				DBG1(DBG_IKE, "  %N: %s, %s",
					 soh_health_class_names, class,
					 status & SOH_MICROSOFT ? "builtin" : product, label);
				if (running)
				{
					this->firewall = TRUE;
				}
				break;
			case SOH_ANTIVIRUS:
				if (running)
				{
					this->antivirus = TRUE;
				}
				goto antilog;
			case SOH_ANTISPYWARE:
				if (running)
				{
					this->antispyware = TRUE;
				}
				goto antilog;
			default:
			antilog:
				DBG1(DBG_IKE, "  %N: %s, %s%s",
					 soh_health_class_names, class,
					 status & SOH_MICROSOFT ? "builtin" : product, label,
					 status & SOH_ENABLED ?
						status & SOH_UP_TO_DATE ?
							", up-to-date" : ", outdated "
						: "");
				break;
		}
	}
}

/**
 * Parse Microsoft SoH attributes
 */
static bool parse_soh_attributes(private_eap_ms_soh_t *this,
								 bio_reader_t *reader)
{
	u_int8_t type;

	while (reader->remaining(reader))
	{
		if (!reader->read_uint8(reader, &type))
		{
			return FALSE;
		}
		switch (type)
		{
			case MS_MACHINE_INVENTORY:
			{
				u_int32_t os_maj, os_min, os_build;
				u_int16_t sp_maj, sp_min, arch;

				if (!reader->read_uint32(reader, &os_maj) ||
					!reader->read_uint32(reader, &os_min) ||
					!reader->read_uint32(reader, &os_build) ||
					!reader->read_uint16(reader, &sp_maj) ||
					!reader->read_uint16(reader, &sp_min) ||
					!reader->read_uint16(reader, &arch))
				{
					return FALSE;
				}
				DBG1(DBG_IKE, "  Windows Version: %d.%d.%d (SP %d.%d) on %N",
					 os_maj, os_min, os_build, sp_maj, sp_min,
					 soh_procarch_names, arch);
				break;
			}
			case MS_PACKET_INFO:
			{
				u_int8_t ver;

				if (!reader->read_uint8(reader, &ver))
				{
					return FALSE;
				}
				break;
			}
			case MS_MACHINENAME:
			{
				chunk_t name;

				if (!reader->read_data16(reader, &name))
				{
					return FALSE;
				}
				DBG1(DBG_IKE, "  Hostname: %.*s", (int)name.len, name.ptr);
				break;
			}
			case MS_CORRELATIONID:
			{
				chunk_t id;

				if (!reader->read_data(reader, 24, &id))
				{
					return FALSE;
				}
				break;
			}
			case MS_QUARANTINE_STATE:
			{
				u_int8_t qstate;
				chunk_t prob, uri;

				if (!reader->read_uint8(reader, &qstate) ||
					!reader->read_uint8(reader, &qstate) ||
					!reader->read_data(reader, 8, &prob) ||
					!reader->read_data16(reader, &uri))
				{
					return FALSE;
				}
				break;
			}
			case MS_MACHINE_INVENTORY_EX:
			{
				u_int32_t reserved;
				u_int8_t product;

				if (!reader->read_uint32(reader, &reserved) ||
					!reader->read_uint8(reader, &product))
				{
					return FALSE;
				}
				break;
			}
			case MS_SYSTEMGENERATED_IDS:
			case MS_INSTALLED_SHVS:
			{
				chunk_t ids;

				if (!reader->read_data16(reader, &ids))
				{
					return FALSE;
				}
				break;
			}
			default:
				return FALSE;
		}
	}
	return TRUE;
}

/**
 * Parse and skip SoH sub header, return FALSE to drop it silently
 */
static bool parse_sub_header(private_eap_ms_soh_t *this, bio_reader_t *reader)
{
	chunk_t id;
	u_int8_t intent, content;

	if (!reader->read_data(reader, 24, &id) ||
		!reader->read_uint8(reader, &intent) ||
		!reader->read_uint8(reader, &content) ||
		content != 0)
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Parse Microsoft Statement of Health batch data
 */
static bool parse_soh_batch(private_eap_ms_soh_t *this, bio_reader_t *reader,
							bool sub_header)
{
	bio_reader_t *inner;
	u_int32_t vendor, status;
	u_int16_t type, length;
	u_int8_t system_health_id = 0, health_class = 0;
	char product[256] = "";
	chunk_t data;

	DBG1(DBG_IKE, "Windows Statement of Health:");

	/* contains:
	 * - one SoH Mode Sub-Header, if SOH_FORMAT_SUB_HEADER
	 * - one SSoH TLV, consisting of:
	 *   - a System Health-ID attribute
	 *   - a vendor specific attribute (MS, actually), containing:
	 *     - a fixed set of MS attributes
	 * - zero or more SoHReportEntry TLV
	 */
	while (reader->remaining(reader))
	{
		if (!reader->read_uint16(reader, &type) ||
			!reader->read_uint16(reader, &length))
		{
			return FALSE;
		}
		switch (type)
		{
			case SOH_VENDOR:
				if (length < sizeof(vendor) ||
					!reader->read_uint32(reader, &vendor) ||
					!reader->read_data(reader, length - sizeof(vendor), &data))
				{
					return FALSE;
				}
				switch (vendor)
				{
					case PEN_MICROSOFT:
						if (sub_header)
						{
							inner = bio_reader_create(data);
							if (!parse_sub_header(this, inner))
							{
								/* we SHOULD ignore this message */
								inner->destroy(inner);
								return TRUE;
							}
							inner->destroy(inner);
							/* only one */
							sub_header = FALSE;
							break;
						}
						inner = bio_reader_create(data);
						if (!parse_soh_attributes(this, inner))
						{
							inner->destroy(inner);
							return FALSE;
						}
						inner->destroy(inner);
						break;
					case 0x00013780:
						/* "Flag" and "Version" fields use the "Microsoft magic
						 * vendor encoding". Both fields not very interesting. */
						break;
					default:
						DBG1(DBG_IKE, "SSOH Vendor %N TLV: %B",
							 pen_names, vendor, &data);
						break;
				}
				break;
			case SOH_SYSTEM_HEALTH_ID:
				if (!reader->read_uint24(reader, &vendor) ||
					!reader->read_uint8(reader, &system_health_id))
				{
					return FALSE;
				}
				break;
			case SOH_HEALTH_CLASS:
				if (!reader->read_uint8(reader, &health_class))
				{
					return FALSE;
				}
				product[0] = 0;
				break;
			case SOH_PRODUCT_NAME:
				if (!reader->read_data(reader, length, &data))
				{
					return FALSE;
				}
				convert_utf16_to_ascii(data, product, sizeof(product));
				break;
			case SOH_HEALTH_CLASS_STATUS:
				if (!reader->read_uint32(reader, &status))
				{
					return FALSE;
				}
				evaluate_status(this, health_class, product, status);
				break;
			default:
				if (!reader->read_data(reader, length, &data))
				{
					return FALSE;
				}
				DBG1(DBG_IKE, "%N: %B", soh_tlv_names, type, &data);
				break;
		}
	}
	return TRUE;
}

/**
 * Parse Statement of Health
 */
static bool parse_soh(private_eap_ms_soh_t *this, bio_reader_t *reader)
{
	bio_reader_t *inner;
	u_int32_t vendor;
	u_int16_t type, length, inner_type;
	chunk_t data;

	while (reader->remaining(reader))
	{
		bool sub_header = TRUE;

		if (!reader->read_uint16(reader, &type) ||
			!reader->read_uint16(reader, &length))
		{
			return FALSE;
		}
		switch (type)
		{
			case SOH_VENDOR:
				if (!reader->read_uint32(reader, &vendor))
				{
					return FALSE;
				}
				switch (vendor)
				{
					case PEN_MICROSOFT:
						if (!reader->read_uint16(reader, &inner_type) ||
							!reader->read_data16(reader, &data))
						{
							return FALSE;
						}
						switch (inner_type)
						{
							case SOH_FORMAT_DEFAULT:
								sub_header = FALSE;
								/* fall */
							case SOH_FORMAT_SUB_HEADER:
								inner = bio_reader_create(data);
								if (!parse_soh_batch(this, inner, sub_header))
								{
									inner->destroy(inner);
									return FALSE;
								}
								inner->destroy(inner);
								break;
							default:
								DBG1(DBG_IKE, "ignoring unknown SoH format");
								break;
						}
						break;
					default:
						DBG1(DBG_IKE, "ignoring %N Vendor SoH TLV",
							 pen_names, vendor);
						if (!reader->read_data(reader, length, &data))
						{
							return FALSE;
						}
						break;
				}
				break;
			default:
				DBG1(DBG_IKE, "ignoring SoH TLV %d", type);
				if (!reader->read_data(reader, length, &data))
				{
					return FALSE;
				}
				break;
		}
	}
	return TRUE;
}

/**
 * Parse Microsoft vendor TLV
 */
static bool parse_ms_tlvs(private_eap_ms_soh_t *this, bio_reader_t *reader)
{
	bio_reader_t *inner;
	u_int16_t type;
	chunk_t data;

	while (reader->remaining(reader))
	{
		if (!reader->read_uint16(reader, &type) ||
			!reader->read_data16(reader, &data))
		{
			return FALSE;
		}
		switch (type)
		{
			case SOH:
				inner = bio_reader_create(data);
				if (!parse_soh(this, inner))
				{
					inner->destroy(inner);
					return FALSE;
				}
				inner->destroy(inner);
				break;
			default:
				DBG1(DBG_IKE, "ignoring MS TLV %d", type);
				break;
		}
	}
	return TRUE;
}

/**
 * Parse contained TLV types
 */
static bool parse_tlv(private_eap_ms_soh_t *this, bio_reader_t *reader)
{
	bio_reader_t *inner;
	u_int16_t type, length;
	u_int32_t vendor;
	chunk_t data;

	if (!reader->read_uint16(reader, &type) ||
		!reader->read_uint16(reader, &length))
	{
		return FALSE;
	}
	switch (type)
	{
		case SOH_VENDOR:
			if (length < sizeof(vendor) ||
				!reader->read_uint32(reader, &vendor) ||
				!reader->read_data(reader, length - sizeof(vendor), &data))
			{
				return FALSE;
			}
			switch (vendor)
			{
				case PEN_MICROSOFT:
					inner = bio_reader_create(data);
					if (!parse_ms_tlvs(this, inner))
					{
						inner->destroy(inner);
						return FALSE;
					}
					inner->destroy(inner);
					break;
				default:
					DBG1(DBG_IKE, "ignoring EAP-SOH %N TLV",
						 pen_names, vendor);
					break;
			}
			break;
		default:
			if (!reader->read_data(reader, length, &data))
			{
				return FALSE;
			}
			break;
	}
	return TRUE;
}

/**
 * Check if the client meets the Health requirements
 */
static bool check_compliance(private_eap_ms_soh_t *this)
{
	/* having update checks enabled sufficient, no Antispyware required */
	return this->firewall && this->antivirus &&
		   this->update >= SOH_UPDATES_CHECK_ONLY &&
		   this->security_updates;
}

METHOD(eap_method_t, process, status_t,
	private_eap_ms_soh_t *this, eap_payload_t *in, eap_payload_t **out)
{
	bio_reader_t *reader;
	u_int8_t code, identifier, type;
	u_int16_t length;
	u_int32_t vendor, vendor_type;

	reader = bio_reader_create(in->get_data(in));

	if (!reader->read_uint8(reader, &code) ||
		!reader->read_uint8(reader, &identifier) ||
		!reader->read_uint16(reader, &length) ||
		!reader->read_uint8(reader, &type) ||
		!reader->read_uint24(reader, &vendor) ||
		!reader->read_uint32(reader, &vendor_type) ||
		code != EAP_RESPONSE || type != EAP_EXPANDED ||
		vendor != PEN_MICROSOFT || vendor_type != EAP_MS_SOH)
	{
		DBG1(DBG_IKE, "received invalid EAP-MS-SOH message");
		reader->destroy(reader);
		return FAILED;
	}

	while (reader->remaining(reader))
	{
		if (!parse_tlv(this, reader))
		{
			reader->destroy(reader);
			DBG1(DBG_IKE, "parsing EAP-MS-SOH message failed!");
			return FAILED;
		}
	}
	reader->destroy(reader);

	if (!check_compliance(this))
	{
		DBG1(DBG_IKE, "client health requirements not met");
		return FAILED;
	}
	return SUCCESS;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_ms_soh_t *this, u_int32_t *vendor)
{
	*vendor = PEN_MICROSOFT;
	return EAP_MS_SOH;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_ms_soh_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, get_identifier, u_int8_t,
	private_eap_ms_soh_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_ms_soh_t *this, u_int8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_ms_soh_t *this)
{
	return TRUE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_ms_soh_t *this)
{
	free(this);
}

/**
 * Generic private constructor
 */
static private_eap_ms_soh_t *create_empty()
{
	private_eap_ms_soh_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
		.update = SOH_UPDATES_NOT_CONFIGURED,
	);

	return this;
}

eap_ms_soh_t *eap_ms_soh_create_server(identification_t *server,
									   identification_t *peer)
{
	return &create_empty()->public;
}

eap_ms_soh_t *eap_ms_soh_create_peer(identification_t *server,
									 identification_t *peer)
{
	return &create_empty()->public;
}
