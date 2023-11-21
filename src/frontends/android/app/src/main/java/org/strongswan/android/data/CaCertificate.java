package org.strongswan.android.data;

import android.database.Cursor;

import java.util.Objects;

import androidx.annotation.NonNull;

public class CaCertificate extends PkcsCertificate
{
	public CaCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String alias,
		@NonNull final String data)
	{
		super(vpnProfileUuid, alias, data);
	}

	public CaCertificate(@NonNull final Cursor cursor)
	{
		super(cursor);
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
		CaCertificate that = (CaCertificate)o;
		return Objects.equals(vpnProfileUuid, that.vpnProfileUuid)
			&& Objects.equals(configuredAlias, that.configuredAlias)
			&& Objects.equals(data, that.data);
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
		return "CaCertificate {" + vpnProfileUuid + ", " + configuredAlias + ", " + effectiveAlias + "}";
	}
}
