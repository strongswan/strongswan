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

package org.strongswan.android.logic.imc;

import android.content.Context;

public class AndroidImc
{
	private final Context mContext;

	public AndroidImc(Context context)
	{
		mContext = context;
	}

	/**
	 * Get a measurement (the binary encoding of the requested attribute) for
	 * the given vendor specific attribute type.
	 *
	 * @param vendor vendor ID
	 * @param type vendor specific attribute type
	 * @return encoded attribute, or null if not available or failed
	 */
	public byte[] getMeasurement(int vendor, int type)
	{
		return null;
	}
}
