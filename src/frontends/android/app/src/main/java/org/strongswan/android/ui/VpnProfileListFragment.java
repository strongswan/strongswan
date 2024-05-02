/*
 * Copyright (C) 2023 Relution GmbH
 * Copyright (C) 2012-2019 Tobias Brunner
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

package org.strongswan.android.ui;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView.MultiChoiceModeListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;
import android.widget.Toast;

import org.strongswan.android.R;
import org.strongswan.android.data.ManagedConfiguration;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.data.VpnProfileSource;
import org.strongswan.android.logic.StrongSwanApplication;
import org.strongswan.android.ui.adapter.VpnProfileAdapter;
import org.strongswan.android.utils.Constants;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import androidx.fragment.app.Fragment;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class VpnProfileListFragment extends Fragment
{
	private static final String SELECTED_KEY = "SELECTED";

	private List<VpnProfile> mVpnProfiles;
	private VpnProfileDataSource mDataSource;
	private VpnProfileAdapter mListAdapter;
	private ListView mListView;
	private OnVpnProfileSelectedListener mListener;
	private Set<Integer> mSelected;
	private boolean mReadOnly;

	private ManagedConfigurationService mManagedConfigurationService;

	private final BroadcastReceiver mProfilesChanged = new BroadcastReceiver()
	{
		@Override
		public void onReceive(Context context, Intent intent)
		{
			String uuid;
			String[] uuids;

			if ((uuid = intent.getStringExtra(Constants.VPN_PROFILES_SINGLE)) != null)
			{
				VpnProfile profile = mDataSource.getVpnProfile(uuid);
				if (profile != null)
				{	/* in case this was an edit, we remove it first */
					mVpnProfiles.remove(profile);
					mVpnProfiles.add(profile);
					mListAdapter.notifyDataSetChanged();
				}
			}
			else if ((uuids = intent.getStringArrayExtra(Constants.VPN_PROFILES_MULTIPLE)) != null)
			{
				for (final String id : uuids)
				{
					final Iterator<VpnProfile> profiles = mVpnProfiles.iterator();
					while (profiles.hasNext())
					{
						final VpnProfile profile = profiles.next();
						if (Objects.equals(profile.getUUID().toString(), id))
						{	/* in case this was an edit, we remove it first */
							profiles.remove();
							break;
						}
					}

					VpnProfile profile = mDataSource.getVpnProfile(id);
					if (profile != null)
					{
						mVpnProfiles.add(profile);
					}
				}
				mListAdapter.notifyDataSetChanged();
			}
		}
	};

	/**
	 * The activity containing this fragment should implement this interface
	 */
	public interface OnVpnProfileSelectedListener
	{
		void onVpnProfileSelected(VpnProfile profile);
	}

	@Override
	public void onInflate(Context context, AttributeSet attrs, Bundle savedInstanceState)
	{
		super.onInflate(context, attrs, savedInstanceState);
		TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.Fragment);
		mReadOnly = a.getBoolean(R.styleable.Fragment_read_only, false);
		a.recycle();
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
							 Bundle savedInstanceState)
	{
		View view = inflater.inflate(R.layout.profile_list_fragment, null);

		mListView = view.findViewById(R.id.profile_list);
		mListView.setAdapter(mListAdapter);
		mListView.setEmptyView(view.findViewById(R.id.profile_list_empty));
		mListView.setOnItemClickListener(mVpnProfileClicked);

		if (!mReadOnly)
		{
			mListView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE_MODAL);
			mListView.setMultiChoiceModeListener(mVpnProfileSelected);
		}
		return view;
	}

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		Bundle args = getArguments();
		if (args != null)
		{
			mReadOnly = args.getBoolean("read_only", mReadOnly);
		}

		if (!mReadOnly)
		{
			setHasOptionsMenu(true);

			ArrayList<Integer> selected = null;
			if (savedInstanceState != null)
			{
				selected = savedInstanceState.getIntegerArrayList(SELECTED_KEY);
			}
			mSelected = selected != null ? new HashSet<>(selected) : new HashSet<>();
		}

		mDataSource = new VpnProfileSource(this.getActivity());
		mDataSource.open();

		mManagedConfigurationService = StrongSwanApplication.getInstance().getManagedConfigurationService();

		/* cached list of profiles used as backend for the ListView */
		mVpnProfiles = mDataSource.getAllVpnProfiles();

		mListAdapter = new VpnProfileAdapter(getActivity(), R.layout.profile_list_item, mVpnProfiles);

		IntentFilter profileChangesFilter = new IntentFilter(Constants.VPN_PROFILES_CHANGED);
		LocalBroadcastManager.getInstance(getActivity()).registerReceiver(mProfilesChanged, profileChangesFilter);
	}

	@Override
	public void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putIntegerArrayList(SELECTED_KEY, new ArrayList<>(mSelected));
	}

	@Override
	public void onDestroy()
	{
		super.onDestroy();
		mDataSource.close();
		LocalBroadcastManager.getInstance(getActivity()).unregisterReceiver(mProfilesChanged);
	}

	@Override
	public void onAttach(Context context)
	{
		super.onAttach(context);

		if (context instanceof OnVpnProfileSelectedListener)
		{
			mListener = (OnVpnProfileSelectedListener)context;
		}
	}

	@Override
	public void onCreateOptionsMenu(Menu menu, MenuInflater inflater)
	{
		inflater.inflate(R.menu.profile_list, menu);
	}

	@Override
	public void onPrepareOptionsMenu(Menu menu)
	{
		final MenuItem addProfile = menu.findItem(R.id.add_profile);
		if (addProfile != null)
		{
			final ManagedConfiguration managedConfiguration = mManagedConfigurationService.getManagedConfiguration();
			addProfile.setVisible(managedConfiguration.isAllowProfileCreation());
			addProfile.setEnabled(managedConfiguration.isAllowProfileCreation());
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		if (item.getItemId() == R.id.add_profile)
		{
			Intent connectionIntent = new Intent(getActivity(),
												 VpnProfileDetailActivity.class);
			startActivity(connectionIntent);
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	private final OnItemClickListener mVpnProfileClicked = new OnItemClickListener()
	{
		@Override
		public void onItemClick(AdapterView<?> a, View v, int position, long id)
		{
			if (mListener != null)
			{
				mListener.onVpnProfileSelected((VpnProfile)a.getItemAtPosition(position));
			}
		}
	};

	private final MultiChoiceModeListener mVpnProfileSelected = new MultiChoiceModeListener()
	{
		private MenuItem mEditProfile;
		private MenuItem mCopyProfile;
		private MenuItem mDeleteProfile;

		private boolean mCanEdit;
		private boolean mCanCopy;
		private boolean mCanDelete;

		private int mReadOnlyCount;

		@Override
		public boolean onPrepareActionMode(ActionMode mode, Menu menu)
		{
			mEditProfile.setEnabled(mCanEdit);
			mCopyProfile.setEnabled(mCanCopy);
			mDeleteProfile.setEnabled(mCanDelete);
			return true;
		}

		@Override
		public void onDestroyActionMode(ActionMode mode)
		{
			mReadOnlyCount = 0;
			mSelected.clear();
		}

		@Override
		public boolean onCreateActionMode(ActionMode mode, Menu menu)
		{
			MenuInflater inflater = mode.getMenuInflater();
			inflater.inflate(R.menu.profile_list_context, menu);
			mEditProfile = menu.findItem(R.id.edit_profile);
			mCopyProfile = menu.findItem(R.id.copy_profile);
			mDeleteProfile = menu.findItem(R.id.delete_profile);
			mode.setTitle(R.string.select_profiles);
			return true;
		}

		@Override
		public boolean onActionItemClicked(ActionMode mode, MenuItem item)
		{
			switch (item.getItemId())
			{
				case R.id.edit_profile:
				{
					int position = mSelected.iterator().next();
					VpnProfile profile = (VpnProfile)mListView.getItemAtPosition(position);
					Intent connectionIntent = new Intent(getActivity(), VpnProfileDetailActivity.class);
					connectionIntent.putExtra(VpnProfileDataSource.KEY_UUID, profile.getUUID().toString());
					startActivity(connectionIntent);
					break;
				}
				case R.id.copy_profile:
				{
					int position = mSelected.iterator().next();
					VpnProfile profile = (VpnProfile)mListView.getItemAtPosition(position);
					profile = profile.clone();
					profile.setUUID(UUID.randomUUID());
					profile.setName(String.format(getString(R.string.copied_name), profile.getName()));
					mDataSource.insertProfile(profile);

					Intent intent = new Intent(Constants.VPN_PROFILES_CHANGED);
					intent.putExtra(Constants.VPN_PROFILES_SINGLE, profile.getUUID().toString());
					LocalBroadcastManager.getInstance(getActivity()).sendBroadcast(intent);

					Intent connectionIntent = new Intent(getActivity(), VpnProfileDetailActivity.class);
					connectionIntent.putExtra(VpnProfileDataSource.KEY_UUID, profile.getUUID().toString());
					startActivity(connectionIntent);
					break;
				}
				case R.id.delete_profile:
				{
					ArrayList<VpnProfile> profiles = new ArrayList<>();
					for (int position : mSelected)
					{
						profiles.add((VpnProfile)mListView.getItemAtPosition(position));
					}
					String[] uuids = new String[profiles.size()];
					for (int i = 0; i < profiles.size(); i++)
					{
						VpnProfile profile = profiles.get(i);
						uuids[i] = profile.getUUID().toString();
						mDataSource.deleteVpnProfile(profile);
					}
					Intent intent = new Intent(Constants.VPN_PROFILES_CHANGED);
					intent.putExtra(Constants.VPN_PROFILES_MULTIPLE, uuids);
					LocalBroadcastManager.getInstance(getActivity()).sendBroadcast(intent);
					Toast.makeText(VpnProfileListFragment.this.getActivity(),
								   R.string.profiles_deleted, Toast.LENGTH_SHORT).show();
					break;
				}
				default:
					return false;
			}
			mode.finish();
			return true;
		}

		@Override
		public void onItemCheckedStateChanged(ActionMode mode, int position,
											  long id, boolean checked)
		{
			VpnProfile profile = (VpnProfile)mListView.getItemAtPosition(position);

			if (checked)
			{
				mSelected.add(position);
				mReadOnlyCount += profile.isReadOnly() ? 1 : 0;
			}
			else
			{
				mSelected.remove(position);
				mReadOnlyCount -= profile.isReadOnly() ? 1 : 0;
			}
			final int checkedCount = mSelected.size();
			switch (checkedCount)
			{
				case 0:
					mode.setSubtitle(R.string.no_profile_selected);
					break;
				case 1:
					mode.setSubtitle(R.string.one_profile_selected);
					break;
				default:
					mode.setSubtitle(String.format(getString(R.string.x_profiles_selected), checkedCount));
					break;
			}

			mCanEdit = checkedCount == 1;
			mCanCopy = checkedCount == 1 && mReadOnlyCount == 0;
			mCanDelete = checkedCount > 0 && mReadOnlyCount == 0;

			mode.invalidate();
		}
	};
}
