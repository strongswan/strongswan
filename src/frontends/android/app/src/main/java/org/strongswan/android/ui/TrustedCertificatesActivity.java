/*
 * Copyright (C) 2012-2014 Tobias Brunner
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

import java.security.KeyStore;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.logic.TrustedCertificateManager.TrustedCertificateSource;
import org.strongswan.android.security.TrustedCertificateEntry;
import org.strongswan.android.ui.CertificateDeleteConfirmationDialog.OnCertificateDeleteListener;

import android.app.ActionBar;
import android.app.ActionBar.Tab;
import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

public class TrustedCertificatesActivity extends Activity implements TrustedCertificateListFragment.OnTrustedCertificateSelectedListener, OnCertificateDeleteListener
{
	public static final String SELECT_CERTIFICATE = "org.strongswan.android.action.SELECT_CERTIFICATE";
	private static final String DIALOG_TAG = "Dialog";
	private static final int IMPORT_CERTIFICATE = 0;
	private boolean mSelect;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.trusted_certificates_activity);

		ActionBar actionBar = getActionBar();
		actionBar.setDisplayHomeAsUpEnabled(true);
		actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);

		TrustedCertificatesTabListener listener;
		listener = new TrustedCertificatesTabListener(this, "system", TrustedCertificateSource.SYSTEM);
		actionBar.addTab(actionBar
			.newTab()
			.setText(R.string.system_tab)
			.setTag(listener)
			.setTabListener(listener));
		listener = new TrustedCertificatesTabListener(this, "user", TrustedCertificateSource.USER);
		actionBar.addTab(actionBar
			.newTab()
			.setText(R.string.user_tab)
			.setTag(listener)
			.setTabListener(listener));
		listener = new TrustedCertificatesTabListener(this, "local", TrustedCertificateSource.LOCAL);
		actionBar.addTab(actionBar
			.newTab()
			.setText(R.string.local_tab)
			.setTag(listener)
			.setTabListener(listener));

		if (savedInstanceState != null)
		{
			actionBar.setSelectedNavigationItem(savedInstanceState.getInt("tab", 0));
		}
		mSelect = SELECT_CERTIFICATE.equals(getIntent().getAction());
	}

	@Override
	protected void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putInt("tab", getActionBar().getSelectedNavigationIndex());
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		getMenuInflater().inflate(R.menu.certificates, menu);
		return true;
	}

	@Override
	public boolean onPrepareOptionsMenu(Menu menu)
	{
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
		{
			menu.removeItem(R.id.menu_import_certificate);
		}
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case android.R.id.home:
				finish();
				return true;
			case R.id.menu_reload_certs:
				reloadCertificates();
				return true;
			case R.id.menu_import_certificate:
				Intent intent = new Intent(this, TrustedCertificateImportActivity.class);
				startActivityForResult(intent, IMPORT_CERTIFICATE);
				return true;
		}
		return super.onOptionsItemSelected(item);
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case IMPORT_CERTIFICATE:
				if (resultCode == Activity.RESULT_OK)
				{
					reloadCertificates();
				}
				return;
		}
		super.onActivityResult(requestCode, resultCode, data);
	}

	@Override
	public void onTrustedCertificateSelected(TrustedCertificateEntry selected)
	{
		if (mSelect)
		{
			/* the user selected a certificate, return to calling activity */
			Intent intent = new Intent();
			intent.putExtra(VpnProfileDataSource.KEY_CERTIFICATE, selected.getAlias());
			setResult(Activity.RESULT_OK, intent);
			finish();
		}
		else
		{
			TrustedCertificatesTabListener listener;
			listener = (TrustedCertificatesTabListener)getActionBar().getSelectedTab().getTag();
			if (listener.mTag == "local")
			{
				Bundle args = new Bundle();
				args.putString(CertificateDeleteConfirmationDialog.ALIAS, selected.getAlias());
				CertificateDeleteConfirmationDialog dialog = new CertificateDeleteConfirmationDialog();
				dialog.setArguments(args);
				dialog.show(this.getFragmentManager(), DIALOG_TAG);
			}
		}
	}

	@Override
	public void onDelete(String alias)
	{
		try
		{
			KeyStore store = KeyStore.getInstance("LocalCertificateStore");
			store.load(null, null);
			store.deleteEntry(alias);
			reloadCertificates();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	private void reloadCertificates()
	{
		TrustedCertificateManager.getInstance().reset();
		for (int i = 0; i < getActionBar().getTabCount(); i++)
		{
			Tab tab = getActionBar().getTabAt(i);
			TrustedCertificatesTabListener listener = (TrustedCertificatesTabListener)tab.getTag();
			listener.reset();
		}
	}

	public static class TrustedCertificatesTabListener implements ActionBar.TabListener
	{
		private final String mTag;
		private final TrustedCertificateSource mSource;
		private Fragment mFragment;

		public TrustedCertificatesTabListener(Activity activity, String tag, TrustedCertificateSource source)
		{
			mTag = tag;
			mSource = source;
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
				Bundle args = new Bundle();
				args.putSerializable(TrustedCertificateListFragment.EXTRA_CERTIFICATE_SOURCE, mSource);
				mFragment.setArguments(args);
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

		public void reset()
		{
			if (mFragment != null)
			{
				((TrustedCertificateListFragment)mFragment).reset();
			}
		}
	}
}
