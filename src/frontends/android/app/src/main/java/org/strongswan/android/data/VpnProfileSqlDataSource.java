/*
 * Copyright (C) 2012-2019 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;

import org.strongswan.android.logic.StrongSwanApplication;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class VpnProfileSqlDataSource implements VpnProfileDataSource
{
	private final DatabaseHelper mDbHelper;

	private SQLiteDatabase mDatabase;

	/**
	 * Construct a new VPN profile data source. The context is used to
	 * open/create the database.
	 */
	public VpnProfileSqlDataSource()
	{
		mDbHelper = StrongSwanApplication.getInstance().getDatabaseHelper();
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		if (mDatabase == null)
		{
			mDatabase = mDbHelper.getWritableDatabase();
		}
		return this;
	}

	@Override
	public void close()
	{
		if (mDatabase != null)
		{
			mDatabase = null;
		}
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		ContentValues values = ContentValuesFromVpnProfile(profile);
		long insertId = mDatabase.insert(DatabaseHelper.TABLE_VPN_PROFILE.Name, null, values);
		if (insertId == -1)
		{
			return null;
		}
		profile.setDataSource(this);
		profile.setId(insertId);
		return profile;
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		final UUID uuid = profile.getUUID();
		ContentValues values = ContentValuesFromVpnProfile(profile);
		return mDatabase.update(DatabaseHelper.TABLE_VPN_PROFILE.Name, values, KEY_UUID + " = ?", new String[]{uuid.toString()}) > 0;
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		final UUID uuid = profile.getUUID();
		return mDatabase.delete(DatabaseHelper.TABLE_VPN_PROFILE.Name, KEY_UUID + " = ?", new String[]{uuid.toString()}) > 0;
	}

	@Override
	public VpnProfile getVpnProfile(UUID uuid)
	{
		VpnProfile profile = null;
		DatabaseHelper.DbTable table = DatabaseHelper.TABLE_VPN_PROFILE;
		Cursor cursor = mDatabase.query(table.Name, table.columnNames(), KEY_UUID + " = ?", new String[]{uuid.toString()}, null, null, null);
		if (cursor.moveToFirst())
		{
			profile = VpnProfileFromCursor(cursor);
			profile.setDataSource(this);
		}
		cursor.close();
		return profile;
	}

	@Override
	public List<VpnProfile> getAllVpnProfiles()
	{
		List<VpnProfile> vpnProfiles = new ArrayList<>();

		DatabaseHelper.DbTable table = DatabaseHelper.TABLE_VPN_PROFILE;
		Cursor cursor = mDatabase.query(table.Name, table.columnNames(), null, null, null, null, null);
		cursor.moveToFirst();
		while (!cursor.isAfterLast())
		{
			VpnProfile vpnProfile = VpnProfileFromCursor(cursor);
			vpnProfile.setDataSource(this);
			vpnProfiles.add(vpnProfile);
			cursor.moveToNext();
		}
		cursor.close();
		return vpnProfiles;
	}

	private VpnProfile VpnProfileFromCursor(Cursor cursor)
	{
		VpnProfile profile = new VpnProfile();
		profile.setUUID(UUID.fromString(cursor.getString(cursor.getColumnIndexOrThrow(KEY_UUID))));
		profile.setName(cursor.getString(cursor.getColumnIndexOrThrow(KEY_NAME)));
		profile.setGateway(cursor.getString(cursor.getColumnIndexOrThrow(KEY_GATEWAY)));
		profile.setVpnType(VpnType.fromIdentifier(cursor.getString(cursor.getColumnIndexOrThrow(KEY_VPN_TYPE))));
		profile.setUsername(cursor.getString(cursor.getColumnIndexOrThrow(KEY_USERNAME)));
		profile.setPassword(cursor.getString(cursor.getColumnIndexOrThrow(KEY_PASSWORD)));
		profile.setCertificateAlias(cursor.getString(cursor.getColumnIndexOrThrow(KEY_CERTIFICATE)));
		profile.setUserCertificateAlias(cursor.getString(cursor.getColumnIndexOrThrow(KEY_USER_CERTIFICATE)));
		profile.setMTU(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_MTU)));
		profile.setPort(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_PORT)));
		profile.setSplitTunneling(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_SPLIT_TUNNELING)));
		profile.setLocalId(cursor.getString(cursor.getColumnIndexOrThrow(KEY_LOCAL_ID)));
		profile.setRemoteId(cursor.getString(cursor.getColumnIndexOrThrow(KEY_REMOTE_ID)));
		profile.setExcludedSubnets(cursor.getString(cursor.getColumnIndexOrThrow(KEY_EXCLUDED_SUBNETS)));
		profile.setIncludedSubnets(cursor.getString(cursor.getColumnIndexOrThrow(KEY_INCLUDED_SUBNETS)));
		profile.setSelectedAppsHandling(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_SELECTED_APPS)));
		profile.setSelectedApps(cursor.getString(cursor.getColumnIndexOrThrow(KEY_SELECTED_APPS_LIST)));
		profile.setNATKeepAlive(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_NAT_KEEPALIVE)));
		profile.setFlags(getInt(cursor, cursor.getColumnIndexOrThrow(KEY_FLAGS)));
		profile.setIkeProposal(cursor.getString(cursor.getColumnIndexOrThrow(KEY_IKE_PROPOSAL)));
		profile.setEspProposal(cursor.getString(cursor.getColumnIndexOrThrow(KEY_ESP_PROPOSAL)));
		profile.setDnsServers(cursor.getString(cursor.getColumnIndexOrThrow(KEY_DNS_SERVERS)));
		return profile;
	}

	private ContentValues ContentValuesFromVpnProfile(VpnProfile profile)
	{
		ContentValues values = new ContentValues();
		values.put(KEY_UUID, profile.getUUID().toString());
		values.put(KEY_NAME, profile.getName());
		values.put(KEY_GATEWAY, profile.getGateway());
		values.put(KEY_VPN_TYPE, profile.getVpnType().getIdentifier());
		values.put(KEY_USERNAME, profile.getUsername());
		values.put(KEY_PASSWORD, profile.getPassword());
		values.put(KEY_CERTIFICATE, profile.getCertificateAlias());
		values.put(KEY_USER_CERTIFICATE, profile.getUserCertificateAlias());
		values.put(KEY_MTU, profile.getMTU());
		values.put(KEY_PORT, profile.getPort());
		values.put(KEY_SPLIT_TUNNELING, profile.getSplitTunneling());
		values.put(KEY_LOCAL_ID, profile.getLocalId());
		values.put(KEY_REMOTE_ID, profile.getRemoteId());
		values.put(KEY_EXCLUDED_SUBNETS, profile.getExcludedSubnets());
		values.put(KEY_INCLUDED_SUBNETS, profile.getIncludedSubnets());
		values.put(KEY_SELECTED_APPS, profile.getSelectedAppsHandling().getValue());
		values.put(KEY_SELECTED_APPS_LIST, profile.getSelectedApps());
		values.put(KEY_NAT_KEEPALIVE, profile.getNATKeepAlive());
		values.put(KEY_FLAGS, profile.getFlags());
		values.put(KEY_IKE_PROPOSAL, profile.getIkeProposal());
		values.put(KEY_ESP_PROPOSAL, profile.getEspProposal());
		values.put(KEY_DNS_SERVERS, profile.getDnsServers());
		return values;
	}

	private Integer getInt(Cursor cursor, int columnIndex)
	{
		return cursor.isNull(columnIndex) ? null : cursor.getInt(columnIndex);
	}
}
