package org.strongswan.android.data;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class DatabaseHelperTest
{
	@Rule
	public MockitoRule rule = MockitoJUnit.rule();

	@Mock
	private SQLiteDatabase database;
	@Mock
	private Cursor cursor;

	private final DatabaseHelper databaseHelper = new DatabaseHelper(null);

	@Test
	public void onCreate()
	{
		databaseHelper.onCreate(database);

		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS vpnprofile (_id INTEGER PRIMARY KEY AUTOINCREMENT,_uuid TEXT UNIQUE,name TEXT NOT NULL,gateway TEXT NOT NULL,vpn_type TEXT NOT NULL DEFAULT '',username TEXT,password TEXT,certificate TEXT,user_certificate TEXT,mtu INTEGER,port INTEGER,split_tunneling INTEGER,local_id TEXT,remote_id TEXT,excluded_subnets TEXT,included_subnets TEXT,selected_apps INTEGER,selected_apps_list TEXT,nat_keepalive INTEGER,flags INTEGER,ike_proposal TEXT,esp_proposal TEXT,dns_servers TEXT);");
		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS usercertificate (_id INTEGER PRIMARY KEY AUTOINCREMENT,vpn_profile_uuid TEXT UNIQUE,configured_alias TEXT NOT NULL,effective_alias TEXT,data TEXT NOT NULL,password TEXT);");
		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS cacertificate (_id INTEGER PRIMARY KEY AUTOINCREMENT,vpn_profile_uuid TEXT UNIQUE,configured_alias TEXT NOT NULL,effective_alias TEXT,data TEXT NOT NULL);");
	}

	@Test
	public void onUpgradeFrom1To2()
	{
		databaseHelper.onUpgrade(database, 1, 2);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD user_certificate TEXT;");
	}

	@Test
	public void onUpgradeFrom2To3()
	{
		databaseHelper.onUpgrade(database, 2, 3);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD vpn_type TEXT NOT NULL DEFAULT '';");
	}

	@Test
	public void onUpgradeFrom3To4()
	{
		databaseHelper.onUpgrade(database, 3, 4);

		then(database).should().beginTransaction();
		then(database).should().execSQL("ALTER TABLE vpnprofile RENAME TO tmp_vpnprofile;");
		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS vpnprofile (_id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,gateway TEXT NOT NULL,vpn_type TEXT NOT NULL DEFAULT '',username TEXT,password TEXT,certificate TEXT,user_certificate TEXT);");
		then(database).should().execSQL("INSERT INTO vpnprofile SELECT _id,name,gateway,vpn_type,username,password,certificate,user_certificate FROM tmp_vpnprofile;");
		then(database).should().execSQL("DROP TABLE tmp_vpnprofile;");
		then(database).should().setTransactionSuccessful();
		then(database).should().endTransaction();
	}

	@Test
	public void onUpgradeFrom4To5()
	{
		databaseHelper.onUpgrade(database, 4, 5);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD mtu INTEGER;");
	}

	@Test
	public void onUpgradeFrom5To6()
	{
		databaseHelper.onUpgrade(database, 5, 6);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD port INTEGER;");
	}

	@Test
	public void onUpgradeFrom6To7()
	{
		databaseHelper.onUpgrade(database, 6, 7);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD split_tunneling INTEGER;");
	}

	@Test
	public void onUpgradeFrom7To8()
	{
		databaseHelper.onUpgrade(database, 7, 8);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD local_id TEXT;");
		then(database).should().execSQL("ALTER TABLE vpnprofile ADD remote_id TEXT;");
	}

	@Test
	public void onUpgradeFrom8To9()
	{
		databaseHelper.onUpgrade(database, 8, 9);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD _uuid TEXT UNIQUE;");
	}

	@Test
	public void onUpgradeFrom9To10()
	{
		databaseHelper.onUpgrade(database, 9, 10);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD excluded_subnets TEXT;");
	}

	@Test
	public void onUpgradeFrom10To11()
	{
		databaseHelper.onUpgrade(database, 10, 11);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD included_subnets TEXT;");
	}

	@Test
	public void onUpgradeFrom11To12()
	{
		databaseHelper.onUpgrade(database, 11, 12);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD selected_apps INTEGER;");
		then(database).should().execSQL("ALTER TABLE vpnprofile ADD selected_apps_list TEXT;");
	}

	@Test
	public void onUpgradeFrom13To14()
	{
		databaseHelper.onUpgrade(database, 13, 14);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD flags INTEGER;");
	}

	@Test
	public void onUpgradeFrom14To15()
	{
		databaseHelper.onUpgrade(database, 14, 15);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD ike_proposal TEXT;");
		then(database).should().execSQL("ALTER TABLE vpnprofile ADD esp_proposal TEXT;");
	}

	@Test
	public void onUpgradeFrom15To16()
	{
		// given
		given(database.query(
			"vpnprofile",
			new String[]{
				"_id",
				"_uuid",
				"name",
				"gateway",
				"vpn_type",
				"username",
				"password",
				"certificate",
				"user_certificate",
				"mtu",
				"port",
				"split_tunneling",
				"local_id",
				"remote_id",
				"excluded_subnets",
				"included_subnets",
				"selected_apps",
				"selected_apps_list",
				"nat_keepalive",
				"flags",
				"ike_proposal",
				"esp_proposal",
			},
			"_uuid is NULL",
			null,
			null,
			null,
			null))
			.willReturn(cursor);

		given(cursor.isAfterLast())
			.willReturn(false)
			.willReturn(true);

		given(cursor.getLong(cursor.getColumnIndexOrThrow("_id")))
			.willReturn(1L);

		// when
		databaseHelper.onUpgrade(database, 15, 16);

		// then
		then(database).should().beginTransaction();
		then(database).should().update(eq("vpnprofile"), any(ContentValues.class), eq("_id = 1"), eq(null));

		then(cursor).should().close();

		then(database).should().setTransactionSuccessful();
		then(database).should().endTransaction();
	}

	@Test
	public void onUpgradeFrom16To17()
	{
		databaseHelper.onUpgrade(database, 16, 17);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD dns_servers TEXT;");
	}

	@Test
	public void onUpgradeFrom17To18()
	{
		databaseHelper.onUpgrade(database, 17, 18);

		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS usercertificate (_id INTEGER PRIMARY KEY AUTOINCREMENT,vpn_profile_uuid TEXT UNIQUE,configured_alias TEXT NOT NULL,effective_alias TEXT,data TEXT NOT NULL,password TEXT);");
		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS cacertificate (_id INTEGER PRIMARY KEY AUTOINCREMENT,vpn_profile_uuid TEXT UNIQUE,configured_alias TEXT NOT NULL,effective_alias TEXT,data TEXT NOT NULL);");
	}

	@Test
	public void onUpgradeFrom2To5()
	{
		databaseHelper.onUpgrade(database, 2, 5);

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD vpn_type TEXT NOT NULL DEFAULT '';");

		then(database).should().beginTransaction();
		then(database).should().execSQL("ALTER TABLE vpnprofile RENAME TO tmp_vpnprofile;");
		then(database).should().execSQL("CREATE TABLE IF NOT EXISTS vpnprofile (_id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,gateway TEXT NOT NULL,vpn_type TEXT NOT NULL DEFAULT '',username TEXT,password TEXT,certificate TEXT,user_certificate TEXT);");
		then(database).should().execSQL("INSERT INTO vpnprofile SELECT _id,name,gateway,vpn_type,username,password,certificate,user_certificate FROM tmp_vpnprofile;");
		then(database).should().execSQL("DROP TABLE tmp_vpnprofile;");
		then(database).should().setTransactionSuccessful();
		then(database).should().endTransaction();

		then(database).should().execSQL("ALTER TABLE vpnprofile ADD mtu INTEGER;");
	}
}
