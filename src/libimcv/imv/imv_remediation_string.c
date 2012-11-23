/*
 * Copyright (C) 2012 Andreas Steffen
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

#include "imv_remediation_string.h"

#include <utils/debug.h>

typedef struct private_imv_remediation_string_t private_imv_remediation_string_t;

/**
 * Private data of an imv_remediation_string_t object.
 */
struct private_imv_remediation_string_t {

	/**
	 * Public members of imv_remediation_string_t
	 */
	imv_remediation_string_t public;

	/**
	 * XML or plaintext encoding
	 */
	bool as_xml;

	/**
	 * Preferred language
	 */
	char *lang;

	/**
	 * Contains the concatenated remediation instructions
	 */
	chunk_t instructions;

};

METHOD(imv_remediation_string_t, add_instruction, void,
	private_imv_remediation_string_t *this, imv_lang_string_t title[],
	imv_lang_string_t description[], imv_lang_string_t itemsheader[],
	linked_list_t *items)
{
	char xml_format[] = "  <instruction>\n"
						"    <title>%s</title>\n"
						"    <description>%s</description>\n"
						"%s%s"
						"  </instruction>\n";
	char *instruction, *format, *s_title, *s_description, *s_itemsheader;
	size_t len;

	s_title = imv_lang_string_select_string(title, this->lang);
	s_description = imv_lang_string_select_string(description, this->lang);
	s_itemsheader = imv_lang_string_select_string(itemsheader, this->lang);
	len = strlen(s_title) + strlen(s_description);

	if (this->as_xml)
	{
		format = xml_format;
		len += strlen(xml_format) - 8;
	}
	else
	{
		format = this->instructions.len ? "\n%s\n%s%s%s" : "%s\n%s%s%s";
		len += 2;
	}
	instruction = malloc(len + 1);
	sprintf(instruction, format, s_title, s_description, "", "");
	this->instructions = chunk_cat("mm", this->instructions, 
							chunk_create(instruction, strlen(instruction)));
}

METHOD(imv_remediation_string_t, get_encoding, chunk_t,
	private_imv_remediation_string_t *this)
{
	char xml_header[]  = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
						 "<remediationinstructions>\n";
	char xml_trailer[] = "</remediationinstructions>";

	if (!this->instructions.len)
	{
		return chunk_empty;
	}
	if (this->as_xml)
	{
		this->instructions = chunk_cat("cmc",
								chunk_create(xml_header, strlen(xml_header)),
								this->instructions,
								chunk_create(xml_trailer, strlen(xml_trailer))
							 );
	}
	return this->instructions;
}

METHOD(imv_remediation_string_t, destroy, void,
	private_imv_remediation_string_t *this)
{
	free(this->instructions.ptr);
	free(this);
}

/**
 * Described in header.
 */
imv_remediation_string_t *imv_remediation_string_create(bool as_xml, char *lang)
{
	private_imv_remediation_string_t *this;

	INIT(this,
		.public = {
			.add_instruction = _add_instruction,
			.get_encoding = _get_encoding,
			.destroy = _destroy,
		},
		.as_xml = as_xml,
		.lang = lang,
	);

	return &this->public;
}

