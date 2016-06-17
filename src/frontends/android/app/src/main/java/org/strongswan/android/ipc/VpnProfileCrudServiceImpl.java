/*
 * Copyright Â© 2015 FancyFon Software Ltd.
 * All rights reserved.
 * 
 */
package org.strongswan.android.ipc;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;

import java.util.List;

/**
 * @author Piotr SorĂłbka <piotr.sorobka@fancyfon.com>
 */
public class VpnProfileCrudServiceImpl extends Service {

    public static final String VPN_PROFILE_CRUD_LOCAL_ACTION = "org.strongswan.android.action.BIND_VPN_PROFILE_CRUD_SERVICE_LOCAL";
    private LocalBinder localBinder = new LocalBinder();
    private VpnProfileCrud vpnProfileCrud;

    @Override
    public void onCreate() {
        super.onCreate();
        vpnProfileCrud = new VpnProfileCrud(this);
    }

    @Override
    public void onDestroy() {
        vpnProfileCrud.close();
        super.onDestroy();
    }

    public class LocalBinder extends Binder {
        public VpnProfileCrudServiceImpl getService() {
            return VpnProfileCrudServiceImpl.this;
        }
    }

    private final VpnProfileCrudService.Stub remoteBinder = new VpnProfileCrudService.Stub() {

        @Override
        public boolean createVpnProfile(Bundle vpnProfile) throws RemoteException {
            return vpnProfileCrud.createVpnProfile(vpnProfile);
        }

        @Override
        public Bundle readVpnProfile(long l) throws RemoteException {
            return vpnProfileCrud.readVpnProfile(l);
        }

        @Override
        public List<Bundle> readVpnProfiles() throws RemoteException {
            return vpnProfileCrud.readVpnProfiles();
        }

        @Override
        public boolean updateVpnProfile(Bundle vpnProfile) throws RemoteException {
            return vpnProfileCrud.updateVpnProfile(vpnProfile);
        }

        @Override
        public boolean deleteVpnProfile(String name) throws RemoteException {
            return vpnProfileCrud.deleteVpnProfile(name);
        }

        @Override
        public boolean deleteVpnProfiles() throws RemoteException {
            return vpnProfileCrud.deleteVpnProfiles();
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        if (intent.getAction() != null && intent.getAction().equals(VPN_PROFILE_CRUD_LOCAL_ACTION)) {
            return localBinder;
        }
        return remoteBinder;
    }
}
