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

package org.strongswan.android.data;

import android.content.res.Resources;
import android.os.Bundle;
import org.strongswan.android.R;

import java.util.ArrayList;


public class VpnProfile implements Cloneable
{
	private String mName;
    private String mGateway;
    private String mUsername;
    private String mPassword;
    private String mCertificate;
    private String mUserCertificate;
    private String mCertificateId;
	private ArrayList<String> allowedApplications = new ArrayList<String>();
	private VpnType mVpnType;
	private long mId = -1;

    public VpnProfile() {
    }

    public VpnProfile(Bundle bundle, Resources resources) {
        fromBundle(bundle, resources);
    }

    public long getId()
	{
		return mId;
	}

	public void setId(long id)
	{
		this.mId = id;
	}

	public String getName()
	{
		return mName;
	}

	public void setName(String name)
	{
		this.mName = name;
	}

	public String getGateway()
	{
		return mGateway;
	}

	public void setGateway(String gateway)
	{
		this.mGateway = gateway;
	}

	public VpnType getVpnType()
	{
		return mVpnType;
	}

	public void setVpnType(VpnType type)
	{
		this.mVpnType = type;
	}

	public String getUsername()
	{
		return mUsername;
	}

	public void setUsername(String username)
	{
		this.mUsername = username;
	}

	public String getPassword()
	{
		return mPassword;
	}

	public void setPassword(String password)
	{
		this.mPassword = password;
	}

	public String getCertificateAlias()
	{
		return mCertificate;
	}

	public void setCertificateAlias(String alias)
	{
		this.mCertificate = alias;
	}

	public String getUserCertificateAlias()
	{
		return mUserCertificate;
	}

	public void setUserCertificateAlias(String alias)
	{
		this.mUserCertificate = alias;
	}

	public ArrayList<String> getAllowedApplications() {
		return allowedApplications;
	}

	public void setAllowedApplications(ArrayList<String> allowedApplications) {
		this.allowedApplications = allowedApplications;
	}

    public String getCertificateId() {
        return mCertificateId;
    }

    public void setCertificateId(String mCertificateId) {
        this.mCertificateId = mCertificateId;
    }


    @Override
	public String toString()
	{
		return mName;
	}

	@Override
	public boolean equals(Object o)
	{
		if (o != null && o instanceof VpnProfile)
		{
			return this.mId == ((VpnProfile)o).getId();
		}
		return false;
	}

	@Override
	public VpnProfile clone()
	{
		try
		{
			return (VpnProfile)super.clone();
		}
		catch (CloneNotSupportedException e)
		{
			throw new AssertionError();
		}
	}

    public Bundle toBundle(Resources resources) {
        Bundle bundle = new Bundle();
        bundle.putLong(resources.getString(R.string.vpn_profile_bundle_id_key), getId());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_certificate_alias_key), getCertificateAlias());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), getGateway());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_name_key), getName());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_password_key), getPassword());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_type_key), getVpnType().name());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_alias_key), getUserCertificateAlias());
        bundle.putString(resources.getString(R.string.vpn_profile_bundle_username_key), getUsername());
		bundle.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), getAllowedApplications());
        return bundle;
    }

    private void fromBundle(Bundle bundle, Resources resources) {
        mId = bundle.getLong(resources.getString(R.string.vpn_profile_bundle_id_key));
        mCertificate = bundle.getString(resources.getString(R.string.vpn_profile_bundle_certificate_alias_key));
        mGateway = bundle.getString(resources.getString(R.string.vpn_profile_bundle_gateway_key));
        mName = bundle.getString(resources.getString(R.string.vpn_profile_bundle_name_key));
        mPassword = bundle.getString(resources.getString(R.string.vpn_profile_bundle_password_key));
        mVpnType = VpnType.valueOf(bundle.getString(resources.getString(R.string.vpn_profile_bundle_type_key)));
        mUserCertificate = bundle.getString(resources.getString(R.string.vpn_profile_bundle_user_certificate_alias_key));
        mUsername = bundle.getString(resources.getString(R.string.vpn_profile_bundle_username_key));
 		allowedApplications = bundle.getStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications));
    }
}
