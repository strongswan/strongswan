/*
 * Copyright (C) 2012-2015 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.logic.TrustedCertificateManager.TrustedCertificateSource;
import org.strongswan.android.security.TrustedCertificateEntry;
import org.strongswan.android.ui.CertificateDeleteConfirmationDialog.OnCertificateDeleteListener;

import java.security.KeyStore;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

public class TrustedCertificatesActivity extends AppCompatActivity implements TrustedCertificateListFragment.OnTrustedCertificateSelectedListener, OnCertificateDeleteListener
{
	public static final String SELECT_CERTIFICATE = "org.strongswan.android.action.SELECT_CERTIFICATE";
	private static final String DIALOG_TAG = "Dialog";
	private TrustedCertificatesPagerAdapter mAdapter;
	private ViewPager2 mPager;
	private boolean mSelect;

	private final ActivityResultLauncher<Intent> mImportCertificate = registerForActivityResult(
		new ActivityResultContracts.StartActivityForResult(),
		result -> {
			if (result.getResultCode() == RESULT_OK)
			{
				reloadCertificates();
			}
		}
	);

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.trusted_certificates_activity);

		ActionBar actionBar = getSupportActionBar();
		actionBar.setDisplayHomeAsUpEnabled(true);

		mAdapter = new TrustedCertificatesPagerAdapter(this);

		mPager = (ViewPager2)findViewById(R.id.viewpager);
		mPager.setAdapter(mAdapter);

		TabLayout tabs = (TabLayout)findViewById(R.id.tabs);
		new TabLayoutMediator(tabs, mPager, (tab, position) -> {
			tab.setText(mAdapter.getTitle(position));
		}).attach();

		mSelect = SELECT_CERTIFICATE.equals(getIntent().getAction());
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
				mImportCertificate.launch(intent);
				return true;
		}
		return super.onOptionsItemSelected(item);
	}

	@Override
	public void onTrustedCertificateSelected(TrustedCertificateEntry selected)
	{
		if (mSelect)
		{
			/* the user selected a certificate, return to calling activity */
			Intent intent = new Intent();
			intent.putExtra(VpnProfileDataSource.KEY_CERTIFICATE, selected.getAlias());
			setResult(RESULT_OK, intent);
			finish();
		}
		else if (mAdapter.getSource(mPager.getCurrentItem()) == TrustedCertificateSource.LOCAL)
		{
			Bundle args = new Bundle();
			args.putString(CertificateDeleteConfirmationDialog.ALIAS, selected.getAlias());
			CertificateDeleteConfirmationDialog dialog = new CertificateDeleteConfirmationDialog();
			dialog.setArguments(args);
			dialog.show(getSupportFragmentManager(), DIALOG_TAG);
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
	}

	public static class TrustedCertificatesPagerAdapter extends FragmentStateAdapter
	{
		private TrustedCertificatesTab mTabs[];

		public TrustedCertificatesPagerAdapter(@NonNull FragmentActivity fragmentActivity)
		{
			super(fragmentActivity);
			mTabs = new TrustedCertificatesTab[]{
				new TrustedCertificatesTab(fragmentActivity.getString(R.string.system_tab), TrustedCertificateSource.SYSTEM),
				new TrustedCertificatesTab(fragmentActivity.getString(R.string.user_tab), TrustedCertificateSource.USER),
				new TrustedCertificatesTab(fragmentActivity.getString(R.string.local_tab), TrustedCertificateSource.LOCAL),
			};
		}

		public CharSequence getTitle(int position)
		{
			return mTabs[position].getTitle();
		}

		public TrustedCertificateSource getSource(int position)
		{
			return mTabs[position].getSource();
		}

		@Override
		public int getItemCount()
		{
			return mTabs.length;
		}

		@NonNull
		@Override
		public Fragment createFragment(int position)
		{
			TrustedCertificateListFragment fragment = new TrustedCertificateListFragment();
			Bundle args = new Bundle();
			args.putSerializable(TrustedCertificateListFragment.EXTRA_CERTIFICATE_SOURCE, mTabs[position].getSource());
			fragment.setArguments(args);
			return fragment;
		}
	}

	public static class TrustedCertificatesTab
	{
		private final String mTitle;
		private final TrustedCertificateSource mSource;

		public TrustedCertificatesTab(String title, TrustedCertificateSource source)
		{
			mTitle = title;
			mSource = source;
		}

		public String getTitle()
		{
			return mTitle;
		}

		public TrustedCertificateSource getSource()
		{
			return mSource;
		}
	}
}
