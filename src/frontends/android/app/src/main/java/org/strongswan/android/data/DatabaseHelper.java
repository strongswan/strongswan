package org.strongswan.android.data;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.util.Log;

import java.util.ArrayList;
import java.util.UUID;

public class DatabaseHelper extends SQLiteOpenHelper
{
	private static final String TAG = DatabaseHelper.class.getSimpleName();

	private static final String DATABASE_NAME = "strongswan.db";
	static final String TABLE_VPNPROFILE = "vpnprofile";

	private static final int DATABASE_VERSION = 17;

	private static final DbColumn[] COLUMNS = new DbColumn[]{
		new DbColumn(VpnProfileDataSource.KEY_ID, "INTEGER PRIMARY KEY AUTOINCREMENT", 1),
		new DbColumn(VpnProfileDataSource.KEY_UUID, "TEXT UNIQUE", 9),
		new DbColumn(VpnProfileDataSource.KEY_NAME, "TEXT NOT NULL", 1),
		new DbColumn(VpnProfileDataSource.KEY_GATEWAY, "TEXT NOT NULL", 1),
		new DbColumn(VpnProfileDataSource.KEY_VPN_TYPE, "TEXT NOT NULL", 3),
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
	};

	DatabaseHelper(Context context)
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
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_USER_CERTIFICATE +
				           " TEXT;");
		}
		if (oldVersion < 3)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_VPN_TYPE +
				           " TEXT DEFAULT '';");
		}
		if (oldVersion < 4)
		{    /* remove NOT NULL constraint from username column */
			updateColumns(db, 4);
		}
		if (oldVersion < 5)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_MTU +
				           " INTEGER;");
		}
		if (oldVersion < 6)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_PORT +
				           " INTEGER;");
		}
		if (oldVersion < 7)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_SPLIT_TUNNELING +
				           " INTEGER;");
		}
		if (oldVersion < 8)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_LOCAL_ID +
				           " TEXT;");
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_REMOTE_ID +
				           " TEXT;");
		}
		if (oldVersion < 9)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_UUID +
				           " TEXT;");
			updateColumns(db, 9);
		}
		if (oldVersion < 10)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_EXCLUDED_SUBNETS +
				           " TEXT;");
		}
		if (oldVersion < 11)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_INCLUDED_SUBNETS +
				           " TEXT;");
		}
		if (oldVersion < 12)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_SELECTED_APPS +
				           " INTEGER;");
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_SELECTED_APPS_LIST +
				           " TEXT;");
		}
		if (oldVersion < 13)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_NAT_KEEPALIVE +
				           " INTEGER;");
		}
		if (oldVersion < 14)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_FLAGS +
				           " INTEGER;");
		}
		if (oldVersion < 15)
		{
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_IKE_PROPOSAL +
				           " TEXT;");
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_ESP_PROPOSAL +
				           " TEXT;");
		}
		if (oldVersion < 16)
		{    /* add a UUID to all entries that haven't one yet */
			db.beginTransaction();
			try
			{
				Cursor cursor = db.query(TABLE_VPNPROFILE, getColumns(16), VpnProfileDataSource.KEY_UUID + " is NULL", null, null, null, null);
				for (cursor.moveToFirst(); !cursor.isAfterLast(); cursor.moveToNext())
				{
					ContentValues values = new ContentValues();
					values.put(VpnProfileDataSource.KEY_UUID, UUID.randomUUID().toString());
					db.update(TABLE_VPNPROFILE, values, VpnProfileDataSource.KEY_ID + " = " + cursor.getLong(cursor.getColumnIndexOrThrow(VpnProfileDataSource.KEY_ID)), null);
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
			db.execSQL("ALTER TABLE " + TABLE_VPNPROFILE + " ADD " + VpnProfileDataSource.KEY_DNS_SERVERS +
				           " TEXT;");
		}
	}

	public String[] getAllColumns()
	{
		return getColumns(DATABASE_VERSION);
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

	private String getDatabaseCreate(int version)
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

	private String[] getColumns(int version)
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
