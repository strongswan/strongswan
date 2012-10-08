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

typedef struct private_stroke_counter_t private_stroke_counter_t;

/**
 * Private data of an stroke_counter_t object.
 */
struct private_stroke_counter_t {

	/**
	 * Public stroke_counter_t interface.
	 */
	stroke_counter_t public;

};

METHOD(stroke_counter_t, destroy, void,
	private_stroke_counter_t *this)
{
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
	);

	return &this->public;
}
