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

import org.strongswan.android.logic.imc.attributes.Attribute;
import org.strongswan.android.logic.imc.attributes.AttributeType;
import org.strongswan.android.logic.imc.collectors.Collector;
import org.strongswan.android.logic.imc.collectors.StringVersionCollector;

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
		AttributeType attributeType = AttributeType.fromValues(vendor, type);
		Collector collector = null;

		switch (attributeType)
		{
			case IETF_STRING_VERSION:
				collector = new StringVersionCollector();
				break;
			default:
				break;
		}
		if (collector != null)
		{
			Attribute attribute = collector.getMeasurement();
			if (attribute != null)
			{
				return attribute.getEncoding();
			}
		}
		return null;
	}
}
