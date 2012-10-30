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
import org.strongswan.android.ui.MainActivity;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

public class VpnAppWidgetProvider extends AppWidgetProvider
{
	@Override
	public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds)
	{
		for (int appWidgetId : appWidgetIds)
		{
			updateWidget(context, appWidgetId, VpnAppWidgetConfigure.getProfileId(context, appWidgetId),
						 VpnAppWidgetConfigure.getProfileName(context, appWidgetId));
		}
	}

	@Override
	public void onDeleted(Context context, int[] appWidgetIds)
	{
		for (int appWidgetId : appWidgetIds)
		{
			VpnAppWidgetConfigure.deleteWidgetData(context, appWidgetId);
		}
	}

	@Override
	public void onEnabled(Context context)
	{
		// TODO: register for some yet to add broadcast or bind to VpnStateService
	}

	@Override
	public void onDisabled(Context context)
	{
		// TODO: unregister from broadcasts/service
	}

	/**
	 * Update the given widget with the information from the given VPN profile.
	 *
	 * @param context Context
	 * @param appWidgetId widget to update
	 * @param id Id of VPN profile
	 * @param name Name of VPN profile
	 */
	public static void updateWidget(Context context, int appWidgetId, long id, String name)
	{
		AppWidgetManager appWidgetManager = AppWidgetManager.getInstance(context);
		Intent intent = new Intent(context, MainActivity.class);
		PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

		RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.vpn_appwidget);
		views.setOnClickPendingIntent(R.id.vpn_status, pendingIntent);
		views.setTextViewText(R.id.vpn_profile, name);
		appWidgetManager.updateAppWidget(appWidgetId, views);
	}
}
