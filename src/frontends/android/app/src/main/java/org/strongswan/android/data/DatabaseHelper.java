/*
 * Copyright (C) 2023 Relution GmbH
 * Copyright (C) 2012-2024 Tobias Brunner
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
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.util.Log;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class DatabaseHelper extends SQLiteOpenHelper
{
	private static final String TAG = DatabaseHelper.class.getSimpleName();

	private static final String DATABASE_NAME = "strongswan.db";

	private static final String TABLE_NAME_VPN_PROFILE = "vpnprofile";
	private static final String TABLE_NAME_TRUSTED_CERTIFICATE = "trustedcertificate";
	private static final String TABLE_NAME_USER_CERTIFICATE = "usercertificate";

	static final DbTable TABLE_VPN_PROFILE = new DbTable(TABLE_NAME_VPN_PROFILE, 1, new DbColumn[]{
		new DbColumn(VpnProfileDataSource.KEY_ID, "INTEGER PRIMARY KEY AUTOINCREMENT", 1),
		new DbColumn(VpnProfileDataSource.KEY_UUID, "TEXT UNIQUE", 9),
		new DbColumn(VpnProfileDataSource.KEY_NAME, "TEXT NOT NULL", 1),
		new DbColumn(VpnProfileDataSource.KEY_GATEWAY, "TEXT NOT NULL", 1),
		new DbColumn(VpnProfileDataSource.KEY_VPN_TYPE, "TEXT NOT NULL DEFAULT ''", 3),
		new DbColumn(VpnProfileDataSource.KEY_USERNAME, "TEXT", 1),
		new DbColumn(VpnProfileDataSource.KEY_PASSWORD, "TEXT", 1),
		new DbColumn(VpnProfileDataSource.KEY_CERTIFICATE, "TEXT", 1),
		new DbColumn(VpnProfileDataSource.KEY_USER_CERTIFICATE, "TEXT", 2),
		new DbColumn(VpnProfileDataSource.KEY_MTU, "INTEGER", 5),
		new DbColumn(VpnProfileDataSource.KEY_PORT, "INTEGER", 6),
		new DbColumn(VpnProfileDataSource.KEY_SPLIT_TUNNELING, "INTEGER", 7),
		new DbColumn(VpnProfileDataSource.KEY_LOCAL_ID, "TEXT", 8),
		new DbColumn(VpnProfileDataSource.KEY_REMOTE_ID, "TEXT", 8),
		new DbColumn(VpnProfileDataSource.KEY_EXCLUDED_SUBNETS, "TEXT", 10),
		new DbColumn(VpnProfileDataSource.KEY_INCLUDED_SUBNETS, "TEXT", 11),
		new DbColumn(VpnProfileDataSource.KEY_SELECTED_APPS, "INTEGER", 12),
		new DbColumn(VpnProfileDataSource.KEY_SELECTED_APPS_LIST, "TEXT", 12),
		new DbColumn(VpnProfileDataSource.KEY_NAT_KEEPALIVE, "INTEGER", 13),
		new DbColumn(VpnProfileDataSource.KEY_FLAGS, "INTEGER", 14),
		new DbColumn(VpnProfileDataSource.KEY_IKE_PROPOSAL, "TEXT", 15),
		new DbColumn(VpnProfileDataSource.KEY_ESP_PROPOSAL, "TEXT", 15),
		new DbColumn(VpnProfileDataSource.KEY_DNS_SERVERS, "TEXT", 17),
	});

	public static final DbTable TABLE_TRUSTED_CERTIFICATE = new DbTable(TABLE_NAME_TRUSTED_CERTIFICATE, 18, new DbColumn[]{
		new DbColumn(ManagedCertificate.KEY_ID, "INTEGER PRIMARY KEY AUTOINCREMENT", 18),
		new DbColumn(ManagedCertificate.KEY_VPN_PROFILE_UUID, "TEXT UNIQUE", 18),
		new DbColumn(ManagedCertificate.KEY_ALIAS, "TEXT NOT NULL", 18),
		new DbColumn(ManagedCertificate.KEY_DATA, "TEXT NOT NULL", 18),
	});

	public static final DbTable TABLE_USER_CERTIFICATE = new DbTable(TABLE_NAME_USER_CERTIFICATE, 18, new DbColumn[]{
		new DbColumn(ManagedCertificate.KEY_ID, "INTEGER PRIMARY KEY AUTOINCREMENT", 18),
		new DbColumn(ManagedCertificate.KEY_VPN_PROFILE_UUID, "TEXT UNIQUE", 18),
		new DbColumn(ManagedCertificate.KEY_ALIAS, "TEXT NOT NULL", 18),
		new DbColumn(ManagedCertificate.KEY_DATA, "TEXT NOT NULL", 18),
		new DbColumn(ManagedUserCertificate.KEY_PASSWORD, "TEXT", 18),
	});

	private static final int DATABASE_VERSION = 18;

	private static final Set<DbTable> TABLES;

	static
	{
		TABLES = new HashSet<>();
		TABLES.add(TABLE_VPN_PROFILE);
		TABLES.add(TABLE_TRUSTED_CERTIFICATE);
		TABLES.add(TABLE_USER_CERTIFICATE);
	}

	public DatabaseHelper(Context context)
	{
		super(context, DATABASE_NAME, null, DATABASE_VERSION);
	}

	@Override
	public void onCreate(SQLiteDatabase database)
	{
		addNewTables(database, 0);
	}

	@Override
	public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion)
	{
		Log.w(TAG, "Upgrading database from version " + oldVersion + " to " + newVersion);
		addNewTables(db, oldVersion);
		addNewColumns(db, oldVersion);

		if (oldVersion < 9)
		{
			updateColumns(db, TABLE_VPN_PROFILE);
		}
		if (oldVersion < 16)
		{	/* add a UUID to all entries that haven't one yet */
			db.beginTransaction();
			try
			{
				Cursor cursor = db.query(TABLE_VPN_PROFILE.Name, TABLE_VPN_PROFILE.columnNames(), VpnProfileDataSource.KEY_UUID + " is NULL", null, null, null, null);
				for (cursor.moveToFirst(); !cursor.isAfterLast(); cursor.moveToNext())
				{
					ContentValues values = new ContentValues();
					values.put(VpnProfileDataSource.KEY_UUID, UUID.randomUUID().toString());
					db.update(TABLE_VPN_PROFILE.Name, values, VpnProfileDataSource.KEY_ID + " = " + cursor.getLong(cursor.getColumnIndexOrThrow(VpnProfileDataSource.KEY_ID)), null);
				}
				cursor.close();
				db.setTransactionSuccessful();
			}
			finally
			{
				db.endTransaction();
			}
		}
	}

	private void updateColumns(SQLiteDatabase db, DbTable table)
	{
		db.beginTransaction();
		try
		{
			db.execSQL("ALTER TABLE " + table.Name + " RENAME TO tmp_" + table.Name + ";");
			db.execSQL(getTableCreate(table));
			StringBuilder insert = new StringBuilder("INSERT INTO " + table.Name + " SELECT ");
			SQLiteQueryBuilder.appendColumns(insert, table.columnNames());
			db.execSQL(insert.append(" FROM tmp_" + table.Name + ";").toString());
			db.execSQL("DROP TABLE tmp_" + table.Name + ";");
			db.setTransactionSuccessful();
		}
		finally
		{
			db.endTransaction();
		}
	}

	private static String getTableCreate(DbTable table)
	{
		boolean first = true;
		StringBuilder create = new StringBuilder("CREATE TABLE IF NOT EXISTS ");
		create.append(table.Name);
		create.append(" (");

		for (final DbColumn column : table.getColumns())
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
		create.append(");");
		return create.toString();
	}

	private void addNewTables(final SQLiteDatabase database, final int oldVersion)
	{
		for (final String sql : getTableCreates(oldVersion))
		{
			database.execSQL(sql);
		}
	}

	private List<String> getTableCreates(final int oldVersion)
	{
		List<String> statements = new ArrayList<>(TABLES.size());
		for (final DbTable table : TABLES)
		{
			if (table.Since > oldVersion)
			{
				statements.add(getTableCreate(table));
			}
		}
		return statements;
	}

	private void addNewColumns(final SQLiteDatabase database, final int oldVersion)
	{
		for (final String sql : getAlterTables(oldVersion))
		{
			database.execSQL(sql);
		}
	}

	private List<String> getAlterTables(final int oldVersion)
	{
		List<String> statements = new ArrayList<>(TABLES.size());
		for (final DbTable table : TABLES)
		{
			statements.addAll(getAlterTables(table, oldVersion));
		}
		return statements;
	}

	private static List<String> getAlterTables(DbTable table, final int oldVersion)
	{
		final List<String> sql = new ArrayList<>();

		for (final DbColumn column : table.getColumns())
		{
			if (column.Since > table.Since && column.Since > oldVersion)
			{
				sql.add("ALTER TABLE " + table.Name + " ADD " + column.Name + " " + column.Type + ";");
			}
		}
		return sql;
	}

	public static class DbTable
	{
		public final String Name;
		public final int Since;
		public final DbColumn[] Columns;

		private DbTable(final String name, final int since, final DbColumn[] columns)
		{
			Name = name;
			Since = since;
			Columns = columns;
		}

		private DbColumn[] getColumns()
		{
			return Columns;
		}

		public String[] columnNames()
		{
			final List<String> columnNames = new ArrayList<>(Columns.length);
			for (DbColumn column : Columns)
			{
				columnNames.add(column.Name);
			}
			return columnNames.toArray(new String[0]);
		}
	}

	public static class DbColumn
	{
		public final String Name;
		public final String Type;
		public final int Since;

		private DbColumn(String name, String type, int since)
		{
			Name = name;
			Type = type;
			Since = since;
		}
	}
}
