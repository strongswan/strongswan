package org.strongswan.android.logic;

import android.content.Context;
import android.os.Handler;

import org.strongswan.android.data.CaCertificate;
import org.strongswan.android.data.CaCertificateRepository;
import org.strongswan.android.data.DatabaseHelper;
import org.strongswan.android.data.ManagedConfigurationService;
import org.strongswan.android.utils.Difference;

import java.util.List;
import java.util.concurrent.ExecutorService;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;

public class CaCertificateManager
{
	@NonNull
	private final ExecutorService executorService;
	@NonNull
	private final Handler handler;

	@NonNull
	private final CaCertificateRepository caCertificateRepository;
	@NonNull
	private final CaCertificateInstaller caCertificateInstaller;

	public CaCertificateManager(
		@NonNull final Context context,
		@NonNull final ExecutorService executorService,
		@NonNull final Handler handler,
		@NonNull final ManagedConfigurationService managedConfigurationService,
		@NonNull final DatabaseHelper databaseHelper)
	{
		this.executorService = executorService;
		this.handler = handler;

		this.caCertificateRepository = new CaCertificateRepository(managedConfigurationService, databaseHelper);
		this.caCertificateInstaller = new CaCertificateInstaller(context);
	}

	public void update(@NonNull final Runnable onUpdateCompleted)
	{
		executorService.execute(() -> {
			final List<CaCertificate> configured = caCertificateRepository.getConfiguredCertificates();
			final List<CaCertificate> installed = caCertificateRepository.getInstalledCertificates();

			final Difference<CaCertificate> diff = Difference.between(installed, configured, CaCertificate::getVpnProfileUuid);
			if (diff.isEmpty())
			{
				return;
			}

			for (final CaCertificate insert : diff.getInserts())
			{
				install(insert);
			}

			for (final Pair<CaCertificate, CaCertificate> update : diff.getUpdates())
			{
				remove(update.first);
				install(update.second);
			}

			for (final CaCertificate delete : diff.getDeletes())
			{
				remove(delete);
			}

			TrustedCertificateManager.getInstance().reset();
			TrustedCertificateManager.getInstance().load();
			handler.post(onUpdateCompleted);
		});
	}

	private void install(@NonNull final CaCertificate caCertificate)
	{
		if (caCertificateInstaller.tryInstall(caCertificate))
		{
			caCertificateRepository.addInstalledCertificate(caCertificate);
		}
	}

	private void remove(@NonNull final CaCertificate caCertificate)
	{
		caCertificateInstaller.tryRemove(caCertificate);
		caCertificateRepository.removeInstalledCertificate(caCertificate);
	}
}
