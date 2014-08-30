/*
 * Copyright (C) 2014 Andreas Steffen
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

#include "test_suite.h"

#include <imcv.h>
#include <pa_tnc/pa_tnc_attr.h>
#include <seg/seg_env.h>
#include <seg/seg_contract.h>
#include <ietf/ietf_attr_pa_tnc_error.h>
#include <ita/ita_attr.h>
#include <ita/ita_attr_command.h>
#include <ita/ita_attr_dummy.h>
#include <tcg/seg/tcg_seg_attr_seg_env.h>

#include <tncif_pa_subtypes.h>

static struct {
	uint32_t max_seg_size, next_segs, last_seg_size;
} seg_env_tests[] = {
	{  0, 0,  0 },
	{ 11, 0,  0 },
	{ 12, 3, 12 },
	{ 13, 3,  9 },
	{ 15, 3,  3 },
	{ 16, 2, 16 },
	{ 17, 2, 14 },
	{ 23, 2,  2 },
	{ 24, 1, 24 },
	{ 25, 1, 23 },
	{ 47, 1,  1 },
	{ 48, 0,  0 },	
};

static char command[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static uint32_t id = 0x123456;

START_TEST(test_imcv_seg_env)
{
	pa_tnc_attr_t *attr, *attr1, *base_attr, *base_attr1, *error;
	tcg_seg_attr_seg_env_t *seg_env_attr;
	ita_attr_command_t *ita_attr;
	seg_env_t *seg_env, *seg_env1;
	pen_type_t type;
	uint32_t base_attr_id, max_seg_size, last_seg_size, seg_size, offset;
	uint8_t flags;
	bool last, last_seg;
	chunk_t value, segment, seg;
	int n;

	libimcv_init(FALSE);
	max_seg_size  = seg_env_tests[_i].max_seg_size;
	last_seg_size = seg_env_tests[_i].last_seg_size;
	base_attr = ita_attr_command_create(command);
	base_attr->build(base_attr);

	seg_env = seg_env_create(id, base_attr, max_seg_size);
	if (seg_env_tests[_i].next_segs == 0)
	{
		ck_assert(seg_env == NULL);
	}
	else
	{
		ck_assert(seg_env->get_base_attr_id(seg_env) == id);
		base_attr1 = seg_env->get_base_attr(seg_env, &error);
		ck_assert(base_attr == base_attr1);
		ck_assert(error == NULL);
		base_attr1->destroy(base_attr1);

		for (n = 0; n <= seg_env_tests[_i].next_segs; n++)
		{
			last_seg = (n == seg_env_tests[_i].next_segs);
			seg_size = (last_seg) ? last_seg_size : max_seg_size;
			if (n == 0)
			{
				/* create first segment */
				attr = seg_env->first_segment(seg_env);
			
				seg_env_attr = (tcg_seg_attr_seg_env_t*)attr;
				segment = seg_env_attr->get_segment(seg_env_attr, &flags);
				if (max_seg_size > 12)
				{
					seg = chunk_create(command, seg_size - 12);
					ck_assert(chunk_equals(seg, chunk_skip(segment, 12)));
				}
				ck_assert(flags == (SEG_ENV_FLAG_MORE | SEG_ENV_FLAG_START));
			}
			else
			{
				/* create next segments */
				attr = seg_env->next_segment(seg_env, &last);
				ck_assert(last == last_seg);

				seg_env_attr = (tcg_seg_attr_seg_env_t*)attr;
				segment = seg_env_attr->get_segment(seg_env_attr, &flags);
				seg = chunk_create(command + n * max_seg_size - 12, seg_size);
				ck_assert(chunk_equals(seg, segment));
				ck_assert(flags == last_seg ? SEG_ENV_FLAG_NONE :
											  SEG_ENV_FLAG_MORE);
			}

			/* check built segment envelope attribute */
			value = attr->get_value(attr);
			ck_assert(value.len == 4 + seg_size);
			ck_assert(segment.len == seg_size);
			ck_assert(seg_env_attr->get_base_attr_id(seg_env_attr) == id);

			/* create parse segment envelope attribute from data */
			attr1 = tcg_seg_attr_seg_env_create_from_data(value);
			ck_assert(attr1->process(attr1, &offset) == SUCCESS);
			attr->destroy(attr);

			seg_env_attr = (tcg_seg_attr_seg_env_t*)attr1;
			segment = seg_env_attr->get_segment(seg_env_attr, &flags);
			base_attr_id = seg_env_attr->get_base_attr_id(seg_env_attr);
			ck_assert(base_attr_id == id);

			/* create and update seg_env object on the receiving side */
		 	if (n == 0)
			{
				ck_assert(flags == (SEG_ENV_FLAG_MORE | SEG_ENV_FLAG_START));
				seg_env1 = seg_env_create_from_data(base_attr_id, segment,
													max_seg_size);
			}
			else
			{
				ck_assert(flags == last_seg ? SEG_ENV_FLAG_NONE :
											  SEG_ENV_FLAG_MORE);
				seg_env1->add_segment(seg_env1, segment);
			}
			attr1->destroy(attr1);
		}

		/* check reconstructed base attribute */
		base_attr1 = seg_env1->get_base_attr(seg_env1, &error);
		ck_assert(base_attr1);
		ck_assert(error == NULL);
		type = base_attr1->get_type(base_attr1);
		ck_assert(type.vendor_id == PEN_ITA);
		ck_assert(type.type == ITA_ATTR_COMMAND);
		ita_attr = (ita_attr_command_t*)base_attr1;
		ck_assert(streq(ita_attr->get_command(ita_attr), command));

		seg_env->destroy(seg_env);
		seg_env1->destroy(seg_env1);
		base_attr1->destroy(base_attr1);
	}
	base_attr->destroy(base_attr);
	libimcv_deinit();
}
END_TEST

START_TEST(test_imcv_seg_env_special)
{
	pa_tnc_attr_t *attr, *attr1, *base_attr;
	tcg_seg_attr_seg_env_t *seg_env_attr;
	pen_type_t type;
	seg_env_t *seg_env;
	chunk_t segment;
	uint32_t max_seg_size = 47;
	uint32_t last_seg_size = 1;
	uint32_t offset = 12;

	base_attr = ita_attr_command_create(command);
	base_attr->build(base_attr);

	/* set noskip flag in base attribute */
	base_attr->set_noskip_flag(base_attr, TRUE);

	seg_env = seg_env_create(id, base_attr, max_seg_size);
	attr = seg_env->first_segment(seg_env);
	attr->destroy(attr);

	/* don't return last segment indicator */
	attr = seg_env->next_segment(seg_env, NULL);

	/* build attribute */
	attr->build(attr);

	/* don't return flags */
	seg_env_attr = (tcg_seg_attr_seg_env_t*)attr;
	segment = seg_env_attr->get_segment(seg_env_attr, NULL);
	ck_assert(segment.len == last_seg_size);

	/* get segment envelope attribute reference and destroy it */
	attr1 = attr->get_ref(attr);
	attr1->destroy(attr1);

	/* check some standard methods */
	type = attr->get_type(attr);
	ck_assert(type.vendor_id == PEN_TCG);
	ck_assert(type.type == TCG_SEG_ATTR_SEG_ENV);
	ck_assert(attr->get_noskip_flag(attr) == FALSE);
	attr->set_noskip_flag(attr, TRUE);
	ck_assert(attr->get_noskip_flag(attr) == TRUE);

	/* request next segment which does not exist */
	ck_assert(seg_env->next_segment(seg_env, NULL) == NULL);

	/* create and parse a too short segment envelope attribute */
	attr1 = tcg_seg_attr_seg_env_create_from_data(chunk_empty);
	ck_assert(attr1->process(attr1, &offset) == FAILED);
	ck_assert(offset == 0);
	attr1->destroy(attr1);

	/* create and parse correct segment envelope attribute */
	attr1 = tcg_seg_attr_seg_env_create_from_data(attr->get_value(attr));
	ck_assert(attr1->process(attr1, &offset) == SUCCESS);
	type = attr1->get_type(attr1);
	ck_assert(type.vendor_id == PEN_TCG);
	ck_assert(type.type == TCG_SEG_ATTR_SEG_ENV);
	attr1->destroy(attr1);

	/* cleanup */
	attr->destroy(attr);
	seg_env->destroy(seg_env);
	base_attr->destroy(base_attr);
}
END_TEST

static struct {
	pa_tnc_error_code_t error_code;
	chunk_t segment;
} invalid_tests[] = {
	{ PA_ERROR_INVALID_PARAMETER, { NULL, 0 } },
	{ PA_ERROR_INVALID_PARAMETER, chunk_from_chars(
		0x00, 0xff, 0xff, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x0a)
	},
	{ PA_ERROR_INVALID_PARAMETER, chunk_from_chars(
		0x00, 0x00, 0x90, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d)
	},
	{ PA_ERROR_INVALID_PARAMETER, chunk_from_chars(
		0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c)
	},
	{ PA_ERROR_INVALID_PARAMETER, chunk_from_chars(
		0x00, 0x00, 0x90, 0x2a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x0c)
	},
	{ PA_ERROR_ATTR_TYPE_NOT_SUPPORTED, chunk_from_chars(
		0x80, 0x00, 0x90, 0x2a, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x0c)
	},
	{ PA_ERROR_RESERVED, chunk_from_chars(
		0x00, 0x00, 0x90, 0x2a, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x0c)
	},
	{ PA_ERROR_RESERVED, chunk_from_chars(
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0c)
	},
	{ PA_ERROR_INVALID_PARAMETER, chunk_from_chars(
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c)
	}
};

START_TEST(test_imcv_seg_env_invalid)
{
	seg_env_t *seg_env;
	pen_type_t error_code;
	pa_tnc_attr_t *base_attr, *error;
	ietf_attr_pa_tnc_error_t *error_attr;

	libimcv_init(FALSE);
	seg_env = seg_env_create_from_data(id, invalid_tests[_i].segment, 20);
	base_attr = seg_env->get_base_attr(seg_env, &error);
	ck_assert(base_attr == NULL);
	if (invalid_tests[_i].error_code == PA_ERROR_RESERVED)
	{
		ck_assert(error == NULL);
	}
	else
	{
		ck_assert(error);
		error->build(error);
		error_attr = (ietf_attr_pa_tnc_error_t*)error;
		error_code = error_attr->get_error_code(error_attr);
		ck_assert(error_code.vendor_id == PEN_IETF);
		ck_assert(error_code.type == invalid_tests[_i].error_code);
		error->destroy(error);
	}
	seg_env->destroy(seg_env);
	libimcv_deinit();
}
END_TEST

START_TEST(test_imcv_seg_contract)
{
	seg_contract_t *contract_i, *contract_r;
	tcg_seg_attr_seg_env_t *seg_env_attr;
	ita_attr_command_t *ita_attr;
	pa_tnc_attr_t *attr, *base_attr_i, *base_attr_r, *error;
	pen_type_t type, msg_type = { PEN_ITA, PA_SUBTYPE_ITA_TEST };
	uint32_t max_seg_size, max_attr_size = 1000, issuer_id = 1;
	uint32_t base_attr_id;
	bool more;

	libimcv_init(FALSE);
	max_seg_size  = seg_env_tests[_i].max_seg_size;
	base_attr_r = ita_attr_command_create(command);
	base_attr_r->build(base_attr_r);
	contract_i = seg_contract_create(msg_type, max_attr_size, max_seg_size,
									 TRUE, issuer_id, FALSE);
	contract_r = seg_contract_create(msg_type, max_attr_size, max_seg_size,
									 FALSE, issuer_id, TRUE);
	attr = contract_r->first_segment(contract_r, base_attr_r);

	if (seg_env_tests[_i].next_segs == 0)
	{
		ck_assert(attr == NULL);
	}
	else
	{
		ck_assert(attr);
		seg_env_attr = (tcg_seg_attr_seg_env_t*)attr;
		base_attr_id = seg_env_attr->get_base_attr_id(seg_env_attr);
		ck_assert(base_attr_id == 1);
		base_attr_i = contract_i->add_segment(contract_i, attr, &error, &more);
		ck_assert(base_attr_i == NULL);
		attr->destroy(attr);
		ck_assert(more);
		while (more)
		{
			attr = contract_r->next_segment(contract_r, base_attr_id);
			ck_assert(attr);
			seg_env_attr = (tcg_seg_attr_seg_env_t*)attr;
			base_attr_id = seg_env_attr->get_base_attr_id(seg_env_attr);
			ck_assert(base_attr_id == 1);
			base_attr_i = contract_i->add_segment(contract_i, attr, &error,
												  &more);
			attr->destroy(attr);
		}
		ck_assert(base_attr_i);
		ck_assert(error == NULL);
		type = base_attr_i->get_type(base_attr_i);
		ck_assert(pen_type_equals(type, base_attr_r->get_type(base_attr_r)));
		ita_attr = (ita_attr_command_t*)base_attr_i;
		ck_assert(streq(ita_attr->get_command(ita_attr), command));
		base_attr_i->destroy(base_attr_i);
	}	
	contract_i->destroy(contract_i);
	contract_r->destroy(contract_r);
	base_attr_r->destroy(base_attr_r);
	libimcv_deinit();
}
END_TEST

START_TEST(test_imcv_seg_contract_special)
{
	seg_contract_t *contract_i, *contract_r;
	tcg_seg_attr_seg_env_t *seg_env_attr1, *seg_env_attr2;
	ita_attr_command_t *ita_attr;
	pa_tnc_attr_t *base_attr1_i, *base_attr2_i, *base_attr1_r, *base_attr2_r;
	pa_tnc_attr_t *attr1_f, *attr2_f, *attr1_n, *attr2_n, *attr3, *error;
	pen_type_t type, msg_type = { PEN_ITA, PA_SUBTYPE_ITA_TEST };
	uint32_t max_seg_size, max_attr_size, issuer_id = 1;
	uint32_t base_attr1_id, base_attr2_id;
	char info[512];
	bool oversize, more;

	libimcv_init(FALSE);

	/* create two base attributes to be segmented */
	base_attr1_r = ita_attr_command_create(command);
	base_attr2_r = ita_attr_dummy_create(129);
	base_attr1_r->build(base_attr1_r);
	base_attr2_r->build(base_attr2_r);

	/* create an issuer contract*/
	contract_i = seg_contract_create(msg_type, 1000, 47,
											   TRUE, issuer_id, FALSE);
	ck_assert(pen_type_equals(contract_i->get_msg_type(contract_i), msg_type));
	ck_assert(contract_i->is_issuer(contract_i));
	ck_assert(!contract_i->is_null(contract_i));

	/* set null contract */
	contract_i->set_max_size(contract_i, SEG_CONTRACT_MAX_SIZE_VALUE,
										 SEG_CONTRACT_MAX_SIZE_VALUE);
	ck_assert(contract_i->is_null(contract_i));

	/* set and get maximum attribute and segment sizes */
	contract_i->set_max_size(contract_i, 1000, 47);
	contract_i->get_max_size(contract_i, NULL, NULL);
	contract_i->get_max_size(contract_i, &max_attr_size, &max_seg_size);
	contract_i->get_info_string(contract_i, info, sizeof(info), TRUE);
	ck_assert(max_attr_size == 1000 && max_seg_size == 47);
	ck_assert(!contract_i->is_null(contract_i));
	
	/* create a null responder contract*/
	contract_r = seg_contract_create(msg_type, SEG_CONTRACT_MAX_SIZE_VALUE,
											   SEG_CONTRACT_MAX_SIZE_VALUE,
											   FALSE, issuer_id, TRUE);
	ck_assert(!contract_r->is_issuer(contract_r));
	ck_assert(!contract_r->check_size(contract_r, base_attr2_r, &oversize));
	ck_assert(!oversize);

	/* allow no fragmentation */
	contract_r->set_max_size(contract_r, 1000, SEG_CONTRACT_MAX_SIZE_VALUE);
	ck_assert(!contract_r->is_null(contract_r));
	ck_assert(!contract_r->check_size(contract_r, base_attr2_r, &oversize));
	ck_assert(!oversize);

	/* no maximum size limit and no fragmentation needed */
	contract_r->set_max_size(contract_r, SEG_CONTRACT_MAX_SIZE_VALUE, 141);
	ck_assert(!contract_r->is_null(contract_r));
	ck_assert(!contract_r->check_size(contract_r, base_attr2_r, &oversize));
	ck_assert(!oversize);

	/* oversize base attribute */
	contract_r->set_max_size(contract_r, 140, 47);
	ck_assert(!contract_r->is_null(contract_r));
	ck_assert(!contract_r->check_size(contract_r, base_attr2_r, &oversize));
	ck_assert(oversize);

	/* set final maximum attribute and segment sizes */
	contract_r->set_max_size(contract_r, 141, 47);
	contract_r->get_info_string(contract_r, info, sizeof(info), TRUE);
	ck_assert(contract_r->check_size(contract_r, base_attr2_r, &oversize));
	ck_assert(!oversize);

	/* get first segment of each base attribute */
	attr1_f = contract_r->first_segment(contract_r, base_attr1_r);
	attr2_f = contract_r->first_segment(contract_r, base_attr2_r);
	ck_assert(attr1_f);
	ck_assert(attr2_f);
	seg_env_attr1 = (tcg_seg_attr_seg_env_t*)attr1_f;
	seg_env_attr2 = (tcg_seg_attr_seg_env_t*)attr2_f;
	base_attr1_id = seg_env_attr1->get_base_attr_id(seg_env_attr1);
	base_attr2_id = seg_env_attr2->get_base_attr_id(seg_env_attr2);
	ck_assert(base_attr1_id == 1);
	ck_assert(base_attr2_id == 2);

	/* get second segment of each base attribute */
	attr1_n = contract_r->next_segment(contract_r, 1);
	attr2_n = contract_r->next_segment(contract_r, 2);
	ck_assert(attr1_n);
	ck_assert(attr2_n);

	/* process first segment of first base attribute */
	base_attr1_i = contract_i->add_segment(contract_i, attr1_f, &error, &more);
	ck_assert(base_attr1_i == NULL);
	ck_assert(error == NULL);
	ck_assert(more);

	/* reapply first segment of first base attribute */
	base_attr1_i = contract_i->add_segment(contract_i, attr1_f, &error, &more);
	ck_assert(base_attr1_i == NULL);
	ck_assert(error == NULL);
	ck_assert(more);

	/* process stray second segment of second attribute */
	base_attr2_i = contract_i->add_segment(contract_i, attr2_n, &error, &more);
	ck_assert(base_attr2_i == NULL);
	ck_assert(error == NULL);
	ck_assert(more);

	/* process first segment of second base attribute */
	base_attr2_i = contract_i->add_segment(contract_i, attr2_f, &error, &more);
	ck_assert(base_attr2_i == NULL);
	ck_assert(error == NULL);
	ck_assert(more);

	/* try to get a segment of a non-existing base-attribute */
	attr3 = contract_r->next_segment(contract_r, 3);
	ck_assert(attr3 == NULL);

	/* process second segment of first base attribute */
	base_attr1_i = contract_i->add_segment(contract_i, attr1_n, &error, &more);
	ck_assert(base_attr1_i);
	ck_assert(error == NULL);
	ck_assert(!more);

	/* process second segment of second base attribute */
	base_attr2_i = contract_i->add_segment(contract_i, attr2_n, &error, &more);
	ck_assert(base_attr2_i == NULL);
	ck_assert(error == NULL);
	ck_assert(more);

	/* destroy first and second segments */
	attr1_f->destroy(attr1_f);
	attr2_f->destroy(attr2_f);
	attr1_n->destroy(attr1_n);
	attr2_n->destroy(attr2_n);

	/* request surplus segment of first base attribute */
	attr1_n = contract_r->next_segment(contract_r, 1);
	ck_assert(attr1_n == NULL);

	/* get last segment of second base attribute */
	attr2_n = contract_r->next_segment(contract_r, 2);
	ck_assert(attr2_n);

	/* process last segment of second base attribute */
	base_attr2_i = contract_i->add_segment(contract_i, attr2_n, &error, &more);
	attr2_n->destroy(attr2_n);
	ck_assert(base_attr2_i);
	ck_assert(error == NULL);
	ck_assert(!more);

	/* request surplus segment of second base attribute */
	attr2_n = contract_r->next_segment(contract_r, 2);
	ck_assert(attr2_n == NULL);

	/* compare original with reconstructed base attributes */
	type = base_attr1_i->get_type(base_attr1_i);
	ck_assert(pen_type_equals(type, base_attr1_r->get_type(base_attr1_r)));
	ita_attr = (ita_attr_command_t*)base_attr1_i;
	ck_assert(streq(ita_attr->get_command(ita_attr), command));

	type = base_attr2_i->get_type(base_attr2_i);
	ck_assert(pen_type_equals(type, base_attr2_r->get_type(base_attr2_r)));
	ck_assert(chunk_equals(base_attr2_i->get_value(base_attr2_i),
						   base_attr2_r->get_value(base_attr2_r)));

	/* cleanup */
	base_attr1_r->destroy(base_attr1_r);
	base_attr2_r->destroy(base_attr2_r);
	base_attr1_i->destroy(base_attr1_i);
	base_attr2_i->destroy(base_attr2_i);
	contract_i->destroy(contract_i);
	contract_r->destroy(contract_r);
	libimcv_deinit();
}
END_TEST

Suite *imcv_seg_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("imcv_seg");

	tc = tcase_create("env");
	tcase_add_loop_test(tc, test_imcv_seg_env, 0, countof(seg_env_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("env_special");
	tcase_add_test(tc, test_imcv_seg_env_special);
	suite_add_tcase(s, tc);

	tc = tcase_create("env_invalid");
	tcase_add_loop_test(tc, test_imcv_seg_env_invalid, 0, countof(invalid_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("contract");
	tcase_add_loop_test(tc, test_imcv_seg_contract, 0, countof(seg_env_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("contract_special");
	tcase_add_test(tc, test_imcv_seg_contract_special);
	suite_add_tcase(s, tc);

	return s;
}
