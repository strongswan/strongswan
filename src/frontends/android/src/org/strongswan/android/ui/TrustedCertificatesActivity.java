/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

package org.strongswan.android.ui;

import org.strongswan.android.R;
import org.strongswan.android.data.TrustedCertificateEntry;
import org.strongswan.android.data.VpnProfileDataSource;

import android.app.ActionBar;
import android.app.ActionBar.Tab;
import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.content.Intent;
import android.os.Bundle;
import android.view.MenuItem;

public class TrustedCertificatesActivity extends Activity implements TrustedCertificateListFragment.OnTrustedCertificateSelectedListener
{
	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.trusted_certificates_activity);

		ActionBar actionBar = getActionBar();
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

		actionBar.addTab(actionBar
			.newTab()
			.setText(R.string.system_tab)
			.setTabListener(new TrustedCertificatesTabListener(this, "system", false)));
		actionBar.addTab(actionBar
			.newTab()
			.setText(R.string.user_tab)
			.setTabListener(new TrustedCertificatesTabListener(this, "user", true)));

		if (savedInstanceState != null)
		{
			actionBar.setSelectedNavigationItem(savedInstanceState.getInt("tab", 0));
		}
	}

	@Override
	protected void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putInt("tab", getActionBar().getSelectedNavigationIndex());
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case android.R.id.home:
				finish();
				return true;
		}
		return super.onOptionsItemSelected(item);
	}

	@Override
	public void onTrustedCertificateSelected(TrustedCertificateEntry selected)
	{
		/* the user selected a certificate, return to calling activity */
		Intent intent = new Intent();
		intent.putExtra(VpnProfileDataSource.KEY_CERTIFICATE, selected.getAlias());
		setResult(Activity.RESULT_OK, intent);
		finish();
	}

	public static class TrustedCertificatesTabListener implements ActionBar.TabListener
	{
		private final String mTag;
		private final boolean mUser;
		private Fragment mFragment;

		public TrustedCertificatesTabListener(Activity activity, String tag, boolean user)
		{
			mTag = tag;
			mUser = user;
			/* check to see if we already have a fragment for this tab, probably
			 * from a previously saved state. if so, deactivate it, because the
			 * initial state is that no tab is shown */
			mFragment = activity.getFragmentManager().findFragmentByTag(mTag);
			if (mFragment != null && !mFragment.isDetached())
			{
				FragmentTransaction ft = activity.getFragmentManager().beginTransaction();
				ft.detach(mFragment);
				ft.commit();
			}
		}

		@Override
		public void onTabSelected(Tab tab, FragmentTransaction ft)
		{
			if (mFragment == null)
			{
				mFragment = new TrustedCertificateListFragment();
				if (mUser)
				{	/* use non empty arguments to indicate this */
					mFragment.setArguments(new Bundle());
				}
				ft.add(android.R.id.content, mFragment, mTag);
			}
			else
			{
				ft.attach(mFragment);
			}
		}

		@Override
		public void onTabUnselected(Tab tab, FragmentTransaction ft)
		{
			if (mFragment != null)
			{
				ft.detach(mFragment);
			}
		}

		@Override
		public void onTabReselected(Tab tab, FragmentTransaction ft)
		{
			/* nothing to be done */
		}
	}
}
