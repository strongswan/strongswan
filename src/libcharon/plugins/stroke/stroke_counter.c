/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "stroke_counter.h"

#include <threading/spinlock.h>

ENUM(stroke_counter_type_names,
	COUNTER_INIT_IKE_SA_REKEY, COUNTER_OUT_INFORMATIONAL_RSP,
	"ikeInitRekey",
	"ikeRspRekey",
	"ikeChildSaRekey",
	"ikeInInvalid",
	"ikeInInvalidSpi",
	"ikeInInitReq",
	"ikeInInitRsp",
	"ikeOutInitReq",
	"ikeOutInitRsp",
	"ikeInAuthReq",
	"ikeInAuthRsp",
	"ikeOutAuthReq",
	"ikeOutAuthRsp",
	"ikeInCrChildReq",
	"ikeInCrChildRsp",
	"ikeOutCrChildReq",
	"ikeOutCrChildRsp",
	"ikeInInfoReq",
	"ikeInInfoRsp",
	"ikeOutInfoReq",
	"ikeOutInfoRsp",
);

typedef struct private_stroke_counter_t private_stroke_counter_t;

/**
 * Private data of an stroke_counter_t object.
 */
struct private_stroke_counter_t {

	/**
	 * Public stroke_counter_t interface.
	 */
	stroke_counter_t public;

	/**
	 * Counter values
	 */
	u_int64_t counter[COUNTER_MAX];

	/**
	 * Lock for counter values
	 */
	spinlock_t *lock;
};

METHOD(stroke_counter_t, destroy, void,
	private_stroke_counter_t *this)
{
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
stroke_counter_t *stroke_counter_create()
{
	private_stroke_counter_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.lock = spinlock_create(),
	);

	return &this->public;
}
