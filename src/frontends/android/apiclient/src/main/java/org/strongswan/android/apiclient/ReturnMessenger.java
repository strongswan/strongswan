/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class ReturnMessenger {
    private static final String TAG = ReturnMessenger.class.getSimpleName();
    private static final int SUCCESS = 1;

    @Inject
    Context context;
    @Inject
    Logger logger;

    public Messenger getReturnMessenger() {
        return returnMessenger;
    }

    private Messenger returnMessenger = new Messenger(new Handler() {
        @Override
        public void handleMessage(Message msg) {
            if(msg.what == SUCCESS) {
                Bundle data = msg.getData();
                if(data != null) {
                    long[] ids = data.getLongArray(context.getString(R.string.vpn_profile_bundle_ids_key));
                    if (ids != null) {
                        logVpnProfiles(data, ids);
                        return;
                    }
                }
                logger.logAndToast(TAG, "Operation executed successfully.");
            } else {
                logger.logAndToast(TAG, "Operation failed.");
            }
        }
    });

    private void logVpnProfiles(Bundle data, long[] ids) {
        for (long id : ids) {
            Bundle bundle = data.getBundle(context.getString(R.string.vpn_profile_bundle_id_params_key, id));
            logger.logAndToastVpnProfileBundle(TAG, bundle);
        }
    }

    private int getInteger(int id) {
        return context.getResources().getInteger(id);
    }
}