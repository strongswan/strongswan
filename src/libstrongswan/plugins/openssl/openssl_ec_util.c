/*
 * Copyright (C) 2013 Tobias Brunner
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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_EC

#include "openssl_ec_util.h"

#include <openssl/bn.h>

/*
 * See header
 */
EC_GROUP *openssl_ec_group_for_curve(ec_curve_t curve)
{
	ec_params_t *params;
	BIGNUM *p, *a, *b, *x, *y, *q;
	const BIGNUM *h;
	EC_POINT *G = NULL;
	EC_GROUP *group = NULL, *result = NULL;
	BN_CTX *ctx = NULL;

	params = ec_get_params(curve);
	if (!params)
	{
		return NULL;
	}
	ctx = BN_CTX_new();
	p = BN_bin2bn(params->p.ptr, params->p.len, NULL);
	a = BN_bin2bn(params->a.ptr, params->a.len, NULL);
	b = BN_bin2bn(params->b.ptr, params->b.len, NULL);
	x = BN_bin2bn(params->x.ptr, params->x.len, NULL);
	y = BN_bin2bn(params->y.ptr, params->y.len, NULL);
	q = BN_bin2bn(params->q.ptr, params->q.len, NULL);
	/* all supported groups currently have a cofactor of 1 */
	h = BN_value_one();
	if (!ctx || !p || !a || !b || !x || !y || !q)
	{
		goto failed;
	}
	group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	if (!group)
	{
		goto failed;
	}
	G = EC_POINT_new(group);
	if (!G || !EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx))
	{
		goto failed;
	}
	if (!EC_GROUP_set_generator(group, G, q, h))
	{
		goto failed;
	}
	result = group;

failed:
	if (!result && group)
	{
		EC_GROUP_free(group);
	}
	if (G)
	{
		EC_POINT_free(G);
	}
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(q);
	return result;
}

#endif /* OPENSSL_NO_EC */
