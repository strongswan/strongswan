/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

package org.strongswan.android.ui;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.logic.CharonVpnService;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.ui.VpnProfileListFragment.OnVpnProfileSelectedListener;

import android.app.ActionBar;
import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.Window;

public class MainActivity extends Activity implements OnVpnProfileSelectedListener
{
	private static final int PREPARE_VPN_SERVICE = 0;
	private VpnProfile activeProfile;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		setContentView(R.layout.main);

		ActionBar bar = getActionBar();
		bar.setDisplayShowTitleEnabled(false);

		/* load CA certificates in a background thread */
		setProgressBarIndeterminateVisibility(true);
		new Thread(new Runnable() {
			@Override
			public void run()
			{
				TrustedCertificateManager.getInstance().load();
				runOnUiThread(new Runnable() {
					@Override
					public void run()
					{
						setProgressBarIndeterminateVisibility(false);
					}
				});
			}
		}).start();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		MenuInflater inflater = getMenuInflater();
		inflater.inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case R.id.menu_reload_certs:
				setProgressBarIndeterminateVisibility(true);
				new Thread(new Runnable() {
					@Override
					public void run()
					{
						TrustedCertificateManager.getInstance().reload();
						runOnUiThread(new Runnable() {
							@Override
							public void run()
							{
								setProgressBarIndeterminateVisibility(false);
							}
						});
					}
				}).start();
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Prepare the VpnService. If this succeeds the current VPN profile is
	 * started.
	 */
	protected void prepareVpnService()
	{
		Intent intent = VpnService.prepare(this);
		if (intent != null)
		{
			startActivityForResult(intent, PREPARE_VPN_SERVICE);
		}
		else
		{
			onActivityResult(PREPARE_VPN_SERVICE, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case PREPARE_VPN_SERVICE:
				if (resultCode == RESULT_OK && activeProfile != null)
				{
					Intent intent = new Intent(this, CharonVpnService.class);
					intent.putExtra(VpnProfileDataSource.KEY_ID, activeProfile.getId());
					this.startService(intent);
				}
				break;
			default:
				super.onActivityResult(requestCode, resultCode, data);
		}
	}

	@Override
	public void onVpnProfileSelected(VpnProfile profile)
	{
		activeProfile = profile;
		prepareVpnService();
	}
}
