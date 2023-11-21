package org.strongswan.android.data;

import android.content.Context;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;

import org.strongswan.android.utils.Constants;

import java.util.Collections;
import java.util.List;

import androidx.preference.PreferenceManager;

public class ManagedConfigurationService
{
	private final Context mContext;

	private ManagedConfiguration mManagedConfiguration = new ManagedConfiguration();
	private List<ManagedVpnProfile> mManagedVpnProfiles = Collections.emptyList();

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

	public List<ManagedVpnProfile> getManagedProfiles()
	{
		return mManagedVpnProfiles;
	}
}
