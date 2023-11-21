package org.strongswan.android.data;

import android.content.ContentValues;
import android.database.Cursor;

import java.util.Objects;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class UserCertificate extends PkcsCertificate
{
	public static final String KEY_PASSWORD = "password";

	private final String privateKeyPassword;

	public UserCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String alias,
		@NonNull final String data,
		@Nullable final String password)
	{
		super(vpnProfileUuid, alias, data);
		privateKeyPassword = password;
	}

	public UserCertificate(@NonNull final Cursor cursor)
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
		UserCertificate that = (UserCertificate)o;
		return Objects.equals(vpnProfileUuid, that.vpnProfileUuid)
			&& Objects.equals(configuredAlias, that.configuredAlias)
			&& Objects.equals(data, that.data)
			&& Objects.equals(privateKeyPassword, that.privateKeyPassword);
	}

	@Override
	public int hashCode()
	{
		return Objects.hash(vpnProfileUuid, configuredAlias, data);
	}

	@NonNull
	@Override
	public String toString()
	{
		return "UserCertificate {" + vpnProfileUuid + ", " + configuredAlias + ", " + effectiveAlias + "}";
	}
}
