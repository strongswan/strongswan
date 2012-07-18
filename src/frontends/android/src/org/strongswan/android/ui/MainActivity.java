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

import org.strongswan.android.logic.TrustedCertificateManager;

import android.app.ActionBar;
import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;

public class MainActivity extends Activity
{
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		startVpnService();

		ActionBar bar = getActionBar();
		bar.setDisplayShowTitleEnabled(false);

		/* load CA certificates in a background thread */
		new Thread(new Runnable() {
			@Override
			public void run()
			{
				TrustedCertificateManager.getInstance().load();
			}
		}).start();
	}

	private void startVpnService()
	{
		Intent intent = VpnService.prepare(this);
		if (intent != null)
		{
			startActivityForResult(intent, 0);
		}
		else
		{
			onActivityResult(0, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		if (resultCode == RESULT_OK)
		{
			Intent intent = new Intent(this, CharonVpnService.class);
			startService(intent);
		}
	}
}
