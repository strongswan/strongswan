/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class Logger {

    @Inject
    Context context;

    @Inject
    Resources resources;

    public void logAndToast(String tag, String message) {
        logAndToast(tag, message, null);
    }

    public void logAndToast(String tag, String message, Throwable t) {
        if (t == null) {
            Log.i(tag, message);
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
        } else {
            Log.e(tag, message, t);
            Toast.makeText(context, message + ", cause: " + t, Toast.LENGTH_SHORT).show();
        }
    }

    public void logAndToastVpnProfileBundle(String tag, Bundle bundle) {
        long mId = bundle.getLong(resources.getString(R.string.vpn_profile_bundle_id_key));
        String mGateway = bundle.getString(resources.getString(R.string.vpn_profile_bundle_gateway_key));
        String mName = bundle.getString(resources.getString(R.string.vpn_profile_bundle_name_key));
        String mPassword = bundle.getString(resources.getString(R.string.vpn_profile_bundle_password_key));
        String mVpnType = bundle.getString(resources.getString(R.string.vpn_profile_bundle_type_key));
        String mUsername = bundle.getString(resources.getString(R.string.vpn_profile_bundle_username_key));
        logAndToast(tag, "VpnProfile: id: " + mId + ", name: " + mName + ", gateway: " + mGateway + ", type: " +
                mVpnType +
                ", pass: " + (mPassword == null ? "null" : mPassword) +
                ", user: " + (mUsername == null ? "null" : mUsername)  );

    }
}