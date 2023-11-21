package org.strongswan.android.data;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.SQLException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class VpnProfileManagedDataSource implements VpnProfileDataSource
{
	private static final String NAME_MANAGED_VPN_PROFILES = "org.strongswan.android.data.VpnProfileManagedDataSource.preferences";

	private final ManagedConfigurationService mManagedConfigurationService;
	private final SharedPreferences mSharedPreferences;

	public VpnProfileManagedDataSource(final Context context)
	{
		this.mManagedConfigurationService = new ManagedConfigurationService(context);
		this.mSharedPreferences = context.getSharedPreferences(NAME_MANAGED_VPN_PROFILES, Context.MODE_PRIVATE);
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		mManagedConfigurationService.loadConfiguration();

		final Set<String> actualKeys = new HashSet<>();
		for (final VpnProfile profile : getAllVpnProfiles())
		{
			actualKeys.add(profile.getUUID().toString());
		}

		final Set<String> storedKeys = new HashSet<>(mSharedPreferences.getAll().keySet());
		storedKeys.removeAll(actualKeys);

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		for (String key : storedKeys)
		{
			editor.remove(key);
		}

		editor.apply();
		return this;
	}

	@Override
	public void close()
	{
		// Do nothing
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		return null;
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		final VpnProfile existingProfile = getVpnProfile(profile.getUUID());
		if (existingProfile == null)
		{
			return false;
		}

		final String password = profile.getPassword();
		existingProfile.setPassword(password);

		final SharedPreferences.Editor editor = mSharedPreferences.edit();
		editor.putString(profile.getUUID().toString(), password);
		return editor.commit();
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		return false;
	}

	@Override
	public ManagedVpnProfile getVpnProfile(long id)
	{
		for (ManagedVpnProfile vpnProfile : getAllVpnProfiles())
		{
			if (vpnProfile.getId() == id)
			{
				return vpnProfile;
			}
		}
		return null;
	}

	@Override
	public ManagedVpnProfile getVpnProfile(UUID uuid)
	{
		for (ManagedVpnProfile vpnProfile : getAllVpnProfiles())
		{
			if (uuid != null && uuid.equals(vpnProfile.getUUID()))
			{
				return vpnProfile;
			}
		}
		return null;
	}

	@Override
	public List<ManagedVpnProfile> getAllVpnProfiles()
	{
		final List<ManagedVpnProfile> managedVpnProfiles = mManagedConfigurationService.getManagedProfiles();
		for (final ManagedVpnProfile vpnProfile : managedVpnProfiles)
		{
			final String password = mSharedPreferences.getString(vpnProfile.getUUID().toString(), vpnProfile.getPassword());
			vpnProfile.setPassword(password);
		}
		return managedVpnProfiles;
	}
}
