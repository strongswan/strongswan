/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.res.Resources;
import android.os.*;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;
import org.strongswan.android.ipc.VpnProfileCrudService;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
public class VpnServiceConnector {

    private static final String TAG = VpnServiceConnector.class.getSimpleName();

    @Inject
    Logger logger;
    @Inject
    Context context;
    @Inject
    Resources resources;
    private VpnProfileCrudService service;
    private Messenger messenger;

    private ServiceConnection vpnProfileCrudServiceConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            logger.logAndToast(TAG, "connected to service");
            VpnServiceConnector.this.service = VpnProfileCrudService.Stub.asInterface(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName className) {
            logger.logAndToast(TAG, "disconnected from service");
            service = null;
        }
    };


    private ServiceConnection vpnProfileCrudMessengerServiceConnection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            logger.logAndToast(TAG, "connected to messenger");
            messenger = new Messenger(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName className) {
            logger.logAndToast(TAG, "disconnected from messenger");
            messenger = null;
        }
    };

    public boolean connect() {
        return connectToMessengerService() && connectToService();
    }


    public boolean connectToService() {
        if (service == null) {
            Intent intent = new Intent(resources.getString(R.string.vpn_profile_crud_service_action));
            return context.bindService(intent, vpnProfileCrudServiceConnection, Context.BIND_AUTO_CREATE);
        } else {
            logger.logAndToast(TAG, "already connected to service");
            return true;
        }
    }

    public boolean connectToMessengerService() {
        if (messenger == null) {
            Intent intent = new Intent(resources.getString(R.string.vpn_profile_crud_messenger_service_action));
            return context.bindService(intent, vpnProfileCrudMessengerServiceConnection, Context.BIND_AUTO_CREATE);
        } else {
            logger.logAndToast(TAG, "already connected to messenger");
            return true;
        }
    }

    public Messenger getMessenger() {
        return messenger;
    }

    public VpnProfileCrudService getService() {
        return service;
    }

    public void disconnect() {
        try {
            disconnectFromService();
            disconnectFromMessenger();
        } catch (Exception e) {
            logger.logAndToast(TAG, "Error disconnecting: " + e);
        }
    }

    private void disconnectFromMessenger() {
        if (messenger != null) {
            context.unbindService(vpnProfileCrudMessengerServiceConnection);
            messenger = null;
            logger.logAndToast(TAG, "unbinding from messenger");
        } else {
            logger.logAndToast(TAG, "not connected to messenger");
        }
    }

    private void disconnectFromService() {
        if (service != null) {
            context.unbindService(vpnProfileCrudServiceConnection);
            logger.logAndToast(TAG, "unbinding from service");
            service = null;
        } else {
            logger.logAndToast(TAG, "not connected to service");
        }
    }

}