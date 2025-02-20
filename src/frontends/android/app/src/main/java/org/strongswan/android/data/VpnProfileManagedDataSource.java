/*
 * Copyright (C) 2025 Tobias Brunner
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
import android.content.SharedPreferences;
import android.database.SQLException;

import org.strongswan.android.logic.StrongSwanApplication;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class VpnProfileManagedDataSource implements VpnProfileDataSource
{
	private static final String NAME_MANAGED_VPN_PROFILES = "org.strongswan.android.data.VpnProfileManagedDataSource.preferences";

	private final ManagedConfigurationService mManagedConfigurationService;
	private final SharedPreferences mSharedPreferences;

	public VpnProfileManagedDataSource(final Context context)
	{
		this.mManagedConfigurationService = StrongSwanApplication.getInstance().getManagedConfigurationService();
		this.mSharedPreferences = context.getSharedPreferences(NAME_MANAGED_VPN_PROFILES, Context.MODE_PRIVATE);
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		return this;
	}

	@Override
	public void close()
	{
		/* remove passwords that are no longer referenced by a VPN profile */
		final Set<String> actualKeys = mManagedConfigurationService.getManagedProfiles().keySet();

		final Set<String> storedKeys = new HashSet<>(mSharedPreferences.getAll().keySet());
		storedKeys.removeAll(actualKeys);

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		for (String key : storedKeys)
		{
			editor.remove(key);
		}

		editor.apply();
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		return null;
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		final VpnProfile managedProfile = mManagedConfigurationService.getManagedProfiles().get(profile.getUUID().toString());
		if (managedProfile == null)
		{
			return false;
		}

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		editor.putString(profile.getUUID().toString(), profile.getPassword());
		return editor.commit();
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		return false;
	}

	/**
	 * Clone and prepare the given managed profile before handing it out.
	 * @param managedProfile profile to prepare
	 */
	private VpnProfile prepareVpnProfile(VpnProfile managedProfile)
	{
		final String password = mSharedPreferences.getString(managedProfile.getUUID().toString(), managedProfile.getPassword());
		final VpnProfile vpnProfile = managedProfile.clone();
		vpnProfile.setPassword(password);
		vpnProfile.setDataSource(this);
		return vpnProfile;
	}

	@Override
	public VpnProfile getVpnProfile(UUID uuid)
	{
		final VpnProfile managedProfile = mManagedConfigurationService.getManagedProfiles().get(uuid.toString());
		if (managedProfile != null)
		{
			return prepareVpnProfile(managedProfile);
		}
		return null;
	}

	@Override
	public List<VpnProfile> getAllVpnProfiles()
	{
		final Map<String, ManagedVpnProfile> managedVpnProfiles = mManagedConfigurationService.getManagedProfiles();
		final List<VpnProfile> vpnProfiles = new ArrayList<>();
		for (final VpnProfile managedProfile : managedVpnProfiles.values())
		{
			vpnProfiles.add(prepareVpnProfile(managedProfile));
		}
		return vpnProfiles;
	}
}
