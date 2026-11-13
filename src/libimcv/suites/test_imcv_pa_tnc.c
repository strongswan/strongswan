/*
 * Copyright (C) 2026 raghu netrakar
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

#include "test_suite.h"

#include <imcv.h>
#include <pa_tnc/pa_tnc_msg.h>
#include <pa_tnc/pa_tnc_attr.h>
#include <ietf/ietf_attr_pa_tnc_error.h>

/**
 * PA-TNC message with an IETF Installed Packages attribute that announces
 * one package but ends right after the Package Count field
 */
static char incomplete_attr[] = {
	/* PA-TNC header: version, reserved, message identifier */
	0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
	/* attribute header: flags, PEN_IETF, IETF_ATTR_INSTALLED_PACKAGES, length */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x10,
	/* attribute value: reserved, Package Count */
	0x00, 0x00, 0x00, 0x01,
};

START_TEST(test_imcv_pa_tnc_incomplete_attr)
{
	pa_tnc_msg_t *msg;
	pa_tnc_attr_t *error;
	ietf_attr_pa_tnc_error_t *error_attr;
	enumerator_t *enumerator;
	pen_type_t error_code;
	int count = 0;

	libimcv_init(FALSE);
	msg = pa_tnc_msg_create_from_data(chunk_from_thing(incomplete_attr));
	ck_assert(msg->process(msg) == VERIFY_ERROR);

	enumerator = msg->create_error_enumerator(msg);
	while (enumerator->enumerate(enumerator, &error))
	{
		error_attr = (ietf_attr_pa_tnc_error_t*)error;
		error_code = error_attr->get_error_code(error_attr);
		ck_assert(error_code.vendor_id == PEN_IETF);
		ck_assert(error_code.type == PA_ERROR_INVALID_PARAMETER);
		/* the error offset points to the length field of the attribute */
		ck_assert_int_eq(error_attr->get_offset(error_attr),
						 PA_TNC_HEADER_SIZE + PA_TNC_ATTR_INFO_SIZE);
		count++;
	}
	enumerator->destroy(enumerator);
	ck_assert_int_eq(count, 1);

	msg->destroy(msg);
	libimcv_deinit();
}
END_TEST

Suite *imcv_pa_tnc_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("imcv_pa_tnc");

	tc = tcase_create("incomplete_attr");
	tcase_add_test(tc, test_imcv_pa_tnc_incomplete_attr);
	suite_add_tcase(s, tc);

	return s;
}
