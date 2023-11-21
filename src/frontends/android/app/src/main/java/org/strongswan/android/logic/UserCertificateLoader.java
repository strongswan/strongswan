package org.strongswan.android.logic;

import android.content.Context;
import android.os.Handler;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;

import org.strongswan.android.data.VpnProfile;

import java.security.cert.X509Certificate;
import java.util.concurrent.Executor;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class UserCertificateLoader
{
	private static final String TAG = UserCertificateLoader.class.getSimpleName();

	@NonNull
	private final StrongSwanApplication mApplication;

	@NonNull
	private final Executor mExecutor;
	@NonNull
	private final Handler mHandler;

	public UserCertificateLoader(@NonNull final Context context)
	{
		mApplication = (StrongSwanApplication)context.getApplicationContext();

		mExecutor = mApplication.getExecutor();
		mHandler = mApplication.getHandler();
	}

	@Nullable
	public X509Certificate[] loadCertificateChain(@NonNull String userCertificateAlias)
	{
		X509Certificate[] chain;
		try
		{
			Log.d(TAG, "Load key chain '" + userCertificateAlias + "'");
			chain = KeyChain.getCertificateChain(mApplication, userCertificateAlias);
		}
		catch (final InterruptedException e)
		{
			Thread.currentThread().interrupt();
			chain = null;
		}
		catch (final KeyChainException e)
		{
			e.printStackTrace();
			chain = null;
		}

		return chain;
	}

	@Nullable
	private X509Certificate loadCertificate(@NonNull final VpnProfile vpnProfile)
	{
		X509Certificate[] chain = loadCertificateChain(vpnProfile.getUserCertificateAlias());
		if (chain != null && chain.length > 0)
		{
			return chain[0];
		}
		return null;
	}

	public void loadCertificate(@NonNull final VpnProfile vpnProfile, @NonNull final UserCertificateLoaderCallback callback)
	{
		mExecutor.execute(() -> {
			final X509Certificate certificate = loadCertificate(vpnProfile);
			complete(certificate, callback);
		});
	}

	protected void complete(@Nullable X509Certificate result, @NonNull UserCertificateLoaderCallback callback)
	{
		mHandler.post(() -> callback.onComplete(result));
	}

	/**
	 * Callback interface for the user certificate loader.
	 */
	@FunctionalInterface
	public interface UserCertificateLoaderCallback
	{
		void onComplete(@Nullable final X509Certificate result);
	}
}
