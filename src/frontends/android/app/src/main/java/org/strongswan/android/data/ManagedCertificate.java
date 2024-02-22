/*
 * Copyright (C) 2023 Relution GmbH
 *
 * Copyright (C) secunet Security Networks AG
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

package org.strongswan.android.data;

import android.content.ContentValues;
import android.database.Cursor;

import androidx.annotation.NonNull;

public abstract class ManagedCertificate
{
	public static final String KEY_ID = "_id";
	public static final String KEY_VPN_PROFILE_UUID = "vpn_profile_uuid";
	public static final String KEY_ALIAS = "alias";
	public static final String KEY_DATA = "data";

	long id = -1;

	@NonNull
	final String vpnProfileUuid;

	@NonNull
	String alias;

	@NonNull
	final String data;

	ManagedCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String alias,
		@NonNull final String data)
	{
		this.vpnProfileUuid = vpnProfileUuid;
		this.alias = alias;
		this.data = data;
	}

	ManagedCertificate(@NonNull final Cursor cursor)
	{
		id = cursor.getLong(cursor.getColumnIndexOrThrow(KEY_ID));
		vpnProfileUuid = cursor.getString(cursor.getColumnIndexOrThrow(KEY_VPN_PROFILE_UUID));
		alias = cursor.getString(cursor.getColumnIndexOrThrow(KEY_ALIAS));
		data = cursor.getString(cursor.getColumnIndexOrThrow(KEY_DATA));
	}

	@NonNull
	public ContentValues asContentValues()
	{
		final ContentValues values = new ContentValues();
		values.put(KEY_VPN_PROFILE_UUID, vpnProfileUuid);
		values.put(KEY_ALIAS, alias);
		values.put(KEY_DATA, data);
		return values;
	}

	public long getId()
	{
		return id;
	}

	public void setId(long id)
	{
		this.id = id;
	}

	@NonNull
	public String getVpnProfileUuid()
	{
		return vpnProfileUuid;
	}

	@NonNull
	public String getAlias()
	{
		return alias;
	}

	@NonNull
	public String getData()
	{
		return data;
	}
}
