/*
 * Copyright (C) 2016 Michael Schmoock
 * COCUS Next GmbH <mschmoock@cocus.com>

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

/**
 * @defgroup quota_listener quota_listener
 * @{ @ingroup quota
 */

#ifndef QUOTA_INVOKE_H_
#define QUOTA_INVOKE_H_

#include <sa/ike_sa.h>

#include "quota_accounting.h"

/**
 * Sets up the environment and calls the shell hander
 */
void quota_invoke(ike_sa_t *ike_sa, quota_event_t status, quota_accounting_entry_t* entry);

#endif /** QUOTA_INVOKE_H_ @}*/
