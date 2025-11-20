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

import java.util.Objects;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class ManagedUserCertificate extends ManagedCertificate
{
	public static final String KEY_PASSWORD = "password";

	private final String privateKeyPassword;

	public ManagedUserCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String data,
		@Nullable final String password)
	{
		super(vpnProfileUuid, "user:" + vpnProfileUuid, data);
		privateKeyPassword = password;
	}

	public ManagedUserCertificate(@NonNull final Cursor cursor)
	{
		super(cursor);
		privateKeyPassword = cursor.getString(cursor.getColumnIndexOrThrow(KEY_PASSWORD));
	}

	@NonNull
	@Override
	public ContentValues asContentValues()
	{
		final ContentValues values = super.asContentValues();
		values.put(KEY_PASSWORD, privateKeyPassword);
		return values;
	}

	@Nullable
	public String getPrivateKeyPassword()
	{
		return privateKeyPassword;
	}

	@Override
	public boolean equals(Object o)
	{
		if (this == o)
		{
			return true;
		}
		if (o == null || getClass() != o.getClass())
		{
			return false;
		}
		ManagedUserCertificate that = (ManagedUserCertificate)o;
		return Objects.equals(vpnProfileUuid, that.vpnProfileUuid) &&
			   Objects.equals(data, that.data) &&
			   Objects.equals(privateKeyPassword, that.privateKeyPassword);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(vpnProfileUuid, data);
	}

	@NonNull
	@Override
	public String toString()
	{
		return "ManagedUserCertificate {" + vpnProfileUuid + ", " + alias + "}";
	}
}
