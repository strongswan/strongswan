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
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class VpnProfileSqlDataSource implements VpnProfileDataSource
{
	private static final String TAG = VpnProfileSqlDataSource.class.getSimpleName();

	private static final DbColumn[] COLUMNS = new VpnProfileSqlDataSource.DbColumn[]{
		new VpnProfileSqlDataSource.DbColumn(KEY_ID, "INTEGER PRIMARY KEY AUTOINCREMENT", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_UUID, "TEXT UNIQUE", 9),
		new VpnProfileSqlDataSource.DbColumn(KEY_NAME, "TEXT NOT NULL", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_GATEWAY, "TEXT NOT NULL", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_VPN_TYPE, "TEXT NOT NULL", 3),
		new VpnProfileSqlDataSource.DbColumn(KEY_USERNAME, "TEXT", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_PASSWORD, "TEXT", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_CERTIFICATE, "TEXT", 1),
		new VpnProfileSqlDataSource.DbColumn(KEY_USER_CERTIFICATE, "TEXT", 2),
		new VpnProfileSqlDataSource.DbColumn(KEY_MTU, "INTEGER", 5),
		new VpnProfileSqlDataSource.DbColumn(KEY_PORT, "INTEGER", 6),
		new VpnProfileSqlDataSource.DbColumn(KEY_SPLIT_TUNNELING, "INTEGER", 7),
		new VpnProfileSqlDataSource.DbColumn(KEY_LOCAL_ID, "TEXT", 8),
		new VpnProfileSqlDataSource.DbColumn(KEY_REMOTE_ID, "TEXT", 8),
		new VpnProfileSqlDataSource.DbColumn(KEY_EXCLUDED_SUBNETS, "TEXT", 10),
		new VpnProfileSqlDataSource.DbColumn(KEY_INCLUDED_SUBNETS, "TEXT", 11),
		new VpnProfileSqlDataSource.DbColumn(KEY_SELECTED_APPS, "INTEGER", 12),
		new VpnProfileSqlDataSource.DbColumn(KEY_SELECTED_APPS_LIST, "TEXT", 12),
		new VpnProfileSqlDataSource.DbColumn(KEY_NAT_KEEPALIVE, "INTEGER", 13),
		new VpnProfileSqlDataSource.DbColumn(KEY_FLAGS, "INTEGER", 14),
		new VpnProfileSqlDataSource.DbColumn(KEY_IKE_PROPOSAL, "TEXT", 15),
		new VpnProfileSqlDataSource.DbColumn(KEY_ESP_PROPOSAL, "TEXT", 15),
		new VpnProfileSqlDataSource.DbColumn(KEY_DNS_SERVERS, "TEXT", 17),
	};

	private DatabaseHelper mDbHelper;
	private SQLiteDatabase mDatabase;
	private final Context mContext;

	private static final String DATABASE_NAME = "strongswan.db";
	private static final String TABLE_VPNPROFILE = "vpnprofile";

	private static final int DATABASE_VERSION = 17;

	private static final String[] ALL_COLUMNS = getColumns(DATABASE_VERSION);

	private static String getDatabaseCreate(int version)
	{
		boolean first = true;
		StringBuilder create = new StringBuilder("CREATE TABLE ");
		create.append(TABLE_VPNPROFILE);
		create.append(" (");
		for (DbColumn column : COLUMNS)
		{
			if (column.Since <= version)
			{
				if (!first)
				{
					create.append(",");
				}
				first = false;
				create.append(column.Name);
				create.append(" ");
				create.append(column.Type);
			}
		}
		create.append(");");
		return create.toString();
	}

	private static String[] getColumns(int version)
	{
		ArrayList<String> columns = new ArrayList<>();
		for (DbColumn column : COLUMNS)
		{
			if (column.Since <= version)
			{
				columns.add(column.Name);
			}
		}
		return columns.toArray(new String[0]);
	}

	private static class DatabaseHelper extends SQLiteOpenHelper
	{
		public DatabaseHelper(Context context)
		{
			super(context, DATABASE_NAME, null, DATABASE_VERSION);
		}

		@Override
		public void onCreate(SQLiteDatabase database)
		{
			database.execSQL(getDatabaseCreate(DATABASE_VERSION));
		}

		@Override
		public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion)
		{
			Log.w(TAG, "Upgrading database from version " + oldVersion +
				  " to " + newVersion);
			if (oldVersion < 2)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_USER_CERTIFICATE +
						   " TEXT;");
			}
			if (oldVersion < 3)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_VPN_TYPE +
						   " TEXT DEFAULT '';");
			}
			if (oldVersion < 4)
			{	/* remove NOT NULL constraint from username column */
				updateColumns(db, 4);
			}
			if (oldVersion < 5)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_MTU +
						   " INTEGER;");
			}
			if (oldVersion < 6)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_PORT +
						   " INTEGER;");
			}
			if (oldVersion < 7)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_SPLIT_TUNNELING +
						   " INTEGER;");
			}
			if (oldVersion < 8)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_LOCAL_ID +
						   " TEXT;");
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_REMOTE_ID +
						   " TEXT;");
			}
			if (oldVersion < 9)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_UUID +
						   " TEXT;");
				updateColumns(db, 9);
			}
			if (oldVersion < 10)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_EXCLUDED_SUBNETS +
						   " TEXT;");
			}
			if (oldVersion < 11)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_INCLUDED_SUBNETS +
						   " TEXT;");
			}
			if (oldVersion < 12)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_SELECTED_APPS +
						   " INTEGER;");
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_SELECTED_APPS_LIST +
						   " TEXT;");
			}
			if (oldVersion < 13)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_NAT_KEEPALIVE +
						   " INTEGER;");
			}
			if (oldVersion < 14)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_FLAGS +
						   " INTEGER;");
			}
			if (oldVersion < 15)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_IKE_PROPOSAL +
						   " TEXT;");
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_ESP_PROPOSAL +
						   " TEXT;");
			}
			if (oldVersion < 16)
			{	/* add a UUID to all entries that haven't one yet */
				db.beginTransaction();
				try
				{
					Cursor cursor = db.query(TABLE_VPNPROFILE, getColumns(16), KEY_UUID + " is NULL", null, null, null, null);
					for (cursor.moveToFirst(); !cursor.isAfterLast(); cursor.moveToNext())
					{
						ContentValues values = new ContentValues();
						values.put(KEY_UUID, UUID.randomUUID().toString());
						db.update(TABLE_VPNPROFILE, values, KEY_ID + " = " + cursor.getLong(cursor.getColumnIndexOrThrow(KEY_ID)), null);
					}
					cursor.close();
					db.setTransactionSuccessful();
				}
				finally
				{
					db.endTransaction();
				}
			}
			if (oldVersion < 17)
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + KEY_DNS_SERVERS +
						   " TEXT;");
			}
		}

		private void updateColumns(SQLiteDatabase db, int version)
		{
			db.beginTransaction();
			try
			{
				db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " RENAME TO tmp_" + TABLE_VPNPROFILE + ";");
				db.execSQL(getDatabaseCreate(version));
				StringBuilder insert = new StringBuilder("INSERT INTO " + TABLE_VPNPROFILE + " SELECT ");
				SQLiteQueryBuilder.appendColumns(insert, getColumns(version));
				db.execSQL(insert.append(" FROM tmp_" + TABLE_VPNPROFILE + ";").toString());
				db.execSQL("DROP TABLE tmp_" + TABLE_VPNPROFILE + ";");
				db.setTransactionSuccessful();
			}
			finally
			{
				db.endTransaction();
			}
		}
	}

	/**
	 * Construct a new VPN profile data source. The context is used to
	 * open/create the database.
	 *
	 * @param context context used to access the database
	 */
	public VpnProfileSqlDataSource(Context context)
	{
		this.mContext = context;
	}

	@Override
	public VpnProfileDataSource open() throws SQLException
	{
		if (mDbHelper == null)
		{
			mDbHelper = new DatabaseHelper(mContext);
			mDatabase = mDbHelper.getWritableDatabase();
		}
		return this;
	}

	@Override
	public void close()
	{
		if (mDbHelper != null)
		{
			mDbHelper.close();
			mDbHelper = null;
		}
	}

	@Override
	public VpnProfile insertProfile(VpnProfile profile)
	{
		ContentValues values = ContentValuesFromVpnProfile(profile);
		long insertId = mDatabase.insert(TABLE_VPNPROFILE, null, values);
		if (insertId == -1)
		{
			return null;
		}
		profile.setId(insertId);
		return profile;
	}

	@Override
	public boolean updateVpnProfile(VpnProfile profile)
	{
		final UUID uuid = profile.getUUID();
		ContentValues values = ContentValuesFromVpnProfile(profile);
		return mDatabase.update(TABLE_VPNPROFILE, values, KEY_UUID + " = ?", new String[]{uuid.toString()}) > 0;
	}

	@Override
	public boolean deleteVpnProfile(VpnProfile profile)
	{
		final UUID uuid = profile.getUUID();
		return mDatabase.delete(TABLE_VPNPROFILE, KEY_UUID + " = ?", new String[]{uuid.toString()}) > 0;
	}

	@Override
	public VpnProfile getVpnProfile(UUID uuid)
	{
		VpnProfile profile = null;
		Cursor cursor = mDatabase.query(TABLE_VPNPROFILE, ALL_COLUMNS,
										KEY_UUID + "='" + uuid.toString() + "'", null, null, null, null);
		if (cursor.moveToFirst())
		{
			profile = VpnProfileFromCursor(cursor);
		}
		cursor.close();
		return profile;
	}

	@Override
	public List<VpnProfile> getAllVpnProfiles()
	{
		List<VpnProfile> vpnProfiles = new ArrayList<VpnProfile>();

		Cursor cursor = mDatabase.query(TABLE_VPNPROFILE, ALL_COLUMNS, null, null, null, null, null);
		cursor.moveToFirst();
		while (!cursor.isAfterLast())
		{
			VpnProfile vpnProfile = VpnProfileFromCursor(cursor);
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

	private static class DbColumn
	{
		public final String Name;
		public final String Type;
		public final Integer Since;

		public DbColumn(String name, String type, Integer since)
		{
			Name = name;
			Type = type;
			Since = since;
		}
	}
}