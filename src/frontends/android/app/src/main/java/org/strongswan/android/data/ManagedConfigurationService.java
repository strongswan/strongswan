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

import android.content.Context;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;

import org.strongswan.android.utils.Constants;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import androidx.preference.PreferenceManager;

public class ManagedConfigurationService
{
	private final Context mContext;

	private ManagedConfiguration mManagedConfiguration = new ManagedConfiguration();
	private Map<String, ManagedVpnProfile> mManagedVpnProfiles = Collections.emptyMap();

	public ManagedConfigurationService(final Context context)
	{
		this.mContext = context;
	}

	public void loadConfiguration()
	{
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
		{
			return;
		}

		final RestrictionsManager restrictionsService = mContext.getSystemService(RestrictionsManager.class);
		if (restrictionsService == null)
		{
			return;
		}

		final Bundle configuration = restrictionsService.getApplicationRestrictions();
		if (configuration == null)
		{
			return;
		}

		final ManagedConfiguration managedConfiguration = new ManagedConfiguration(configuration);
		mManagedConfiguration = managedConfiguration;
		mManagedVpnProfiles = managedConfiguration.getVpnProfiles();
	}

	public void updateSettings()
	{
		if (!mManagedConfiguration.isAllowSettingsAccess())
		{
			final SharedPreferences pref = PreferenceManager.getDefaultSharedPreferences(mContext);
			final SharedPreferences.Editor editor = pref.edit();
			editor.putBoolean(Constants.PREF_IGNORE_POWER_WHITELIST, mManagedConfiguration.isIgnoreBatteryOptimizations());
			editor.putString(Constants.PREF_DEFAULT_VPN_PROFILE, mManagedConfiguration.getDefaultVpnProfile());
			editor.apply();
		}
	}

	public ManagedConfiguration getManagedConfiguration()
	{
		return mManagedConfiguration;
	}

	public Map<String, ManagedVpnProfile> getManagedProfiles()
	{
		return mManagedVpnProfiles;
	}
}
