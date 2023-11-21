package org.strongswan.android.data;

import android.content.Context;
import android.database.SQLException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class VpnProfileSource implements VpnProfileDataSource
{
	private final List<VpnProfileDataSource> dataSources = new ArrayList<>();
	private final VpnProfileSqlDataSource vpnProfileSqlDataSource;

	public VpnProfileSource(Context context)
	{
		vpnProfileSqlDataSource = new VpnProfileSqlDataSource(context);

		dataSources.add(vpnProfileSqlDataSource);
		dataSources.add(new VpnProfileManagedDataSource(context));
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		for (final VpnProfileDataSource source : dataSources)
		{
			source.open();
		}
		return this;
	}

	@Override
	public void close()
	{
		for (final VpnProfileDataSource source : dataSources)
		{
			source.close();
		}
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		return vpnProfileSqlDataSource.insertProfile(profile);
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		return profile.getDataSource().updateVpnProfile(profile);
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		return profile.getDataSource().deleteVpnProfile(profile);
	}

	@Override
	public VpnProfile getVpnProfile(long id)
	{
		for (final VpnProfileDataSource source : dataSources)
		{
			final VpnProfile profile = source.getVpnProfile(id);
			if (profile != null)
			{
				return profile;
			}
		}
		return null;
	}

	@Override
	public VpnProfile getVpnProfile(UUID uuid)
	{
		for (final VpnProfileDataSource source : dataSources)
		{
			final VpnProfile profile = source.getVpnProfile(uuid);
			if (profile != null)
			{
				return profile;
			}
		}
		return null;
	}

	@Override
	public List<VpnProfile> getAllVpnProfiles()
	{
		final List<VpnProfile> profiles = new ArrayList<>();

		for (final VpnProfileDataSource source : dataSources)
		{
			profiles.addAll(source.getAllVpnProfiles());
		}

		return profiles;
	}
}
