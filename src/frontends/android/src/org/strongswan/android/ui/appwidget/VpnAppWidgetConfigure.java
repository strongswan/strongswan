/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

package org.strongswan.android.ui.appwidget;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.ui.VpnProfileListFragment.OnVpnProfileSelectedListener;

import android.app.ActionBar;
import android.app.Activity;
import android.appwidget.AppWidgetManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;

public class VpnAppWidgetConfigure extends Activity implements OnVpnProfileSelectedListener
{
	private static final String PREFS_NAME = "org.strongswan.android.ui.appwidget.VpnAppWidget";
	private static final String PREF_ID_KEY = "id_";
	private static final String PREF_NAME_KEY = "name_";

	private int mAppWidgetId = AppWidgetManager.INVALID_APPWIDGET_ID;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.vpn_appwidget_configure);

		ActionBar bar = getActionBar();
		bar.setDisplayShowTitleEnabled(false);

		setResult(RESULT_CANCELED);

		Bundle extras = getIntent().getExtras();
		if (extras != null)
		{
			mAppWidgetId = extras.getInt(AppWidgetManager.EXTRA_APPWIDGET_ID,
										 AppWidgetManager.INVALID_APPWIDGET_ID);
		}

		if (mAppWidgetId == AppWidgetManager.INVALID_APPWIDGET_ID)
		{
			finish();
		}
	}

	@Override
	public void onVpnProfileSelected(VpnProfile profile)
	{
		SharedPreferences.Editor prefs = getSharedPreferences(PREFS_NAME, 0).edit();
		prefs.putLong(PREF_ID_KEY + mAppWidgetId, profile.getId());
		prefs.putString(PREF_NAME_KEY + mAppWidgetId, profile.getName());
		prefs.commit();

		VpnAppWidgetProvider.updateWidget(this, mAppWidgetId, profile.getId(), profile.getName());

		Intent resultValue = new Intent();
		resultValue.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, mAppWidgetId);
		setResult(RESULT_OK, resultValue);
		finish();
	}

	/**
	 * Get the id of the selected profile for the given widget.
	 *
	 * @param context Context
	 * @param appWidgetId Id of the current widget
	 * @return Id of VPN profile
	 */
	public static long getProfileId(Context context, int appWidgetId)
	{
		SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, 0);
		return prefs.getLong(PREF_ID_KEY + appWidgetId, 0);
	}

	/**
	 * Get the name of the selected profile for the given widget.
	 *
	 * @param context Context
	 * @param appWidgetId Id of the current widget
	 * @return Name of VPN profile
	 */
	public static String getProfileName(Context context, int appWidgetId)
	{
		SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, 0);
		return prefs.getString(PREF_NAME_KEY + appWidgetId, "");
	}

	/**
	 * Delete all data stored for the given widget.
	 *
	 * @param context Context
	 * @param appWidgetId Id of the current widget
	 */
	public static void deleteWidgetData(Context context, int appWidgetId)
	{
		SharedPreferences.Editor prefs = context.getSharedPreferences(PREFS_NAME, 0).edit();
		prefs.remove(PREF_ID_KEY + appWidgetId);
		prefs.remove(PREF_NAME_KEY + appWidgetId);
		prefs.commit();
	}
}
