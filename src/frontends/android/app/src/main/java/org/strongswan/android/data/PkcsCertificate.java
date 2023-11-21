package org.strongswan.android.data;

import android.content.ContentValues;
import android.database.Cursor;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public abstract class PkcsCertificate
{
	public static final String KEY_ID = "_id";
	public static final String KEY_VPN_PROFILE_UUID = "vpn_profile_uuid";
	public static final String KEY_CONFIGURED_ALIAS = "configured_alias";
	public static final String KEY_EFFECTIVE_ALIAS = "effective_alias";
	public static final String KEY_DATA = "data";

	long id = -1;

	@NonNull
	final String vpnProfileUuid;

	@NonNull
	final String configuredAlias;
	@Nullable
	String effectiveAlias;

	@NonNull
	final String data;

	PkcsCertificate(
		@NonNull final String vpnProfileUuid,
		@NonNull final String alias,
		@NonNull final String data)
	{
		this.vpnProfileUuid = vpnProfileUuid;
		this.configuredAlias = alias;
		this.data = data;
	}

	PkcsCertificate(@NonNull final Cursor cursor)
	{
		id = cursor.getLong(cursor.getColumnIndexOrThrow(KEY_ID));
		vpnProfileUuid = cursor.getString(cursor.getColumnIndexOrThrow(KEY_VPN_PROFILE_UUID));
		configuredAlias = cursor.getString(cursor.getColumnIndexOrThrow(KEY_CONFIGURED_ALIAS));
		effectiveAlias = cursor.getString(cursor.getColumnIndexOrThrow(KEY_EFFECTIVE_ALIAS));
		data = cursor.getString(cursor.getColumnIndexOrThrow(KEY_DATA));
	}

	@NonNull
	public ContentValues asContentValues()
	{
		final ContentValues values = new ContentValues();
		values.put(KEY_VPN_PROFILE_UUID, vpnProfileUuid);
		values.put(KEY_CONFIGURED_ALIAS, configuredAlias);
		values.put(KEY_EFFECTIVE_ALIAS, effectiveAlias);
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
		if (effectiveAlias != null)
		{
			return effectiveAlias;
		}
		return configuredAlias;
	}

	@NonNull
	public String getConfiguredAlias()
	{
		return configuredAlias;
	}

	public void setEffectiveAlias(@Nullable String effectiveAlias)
	{
		this.effectiveAlias = effectiveAlias;
	}

	@NonNull
	public String getData()
	{
		return data;
	}
}
