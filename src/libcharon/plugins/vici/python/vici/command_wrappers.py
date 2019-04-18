class CommandWrappers(object):
    def version(self):
        """Retrieve daemon and system specific version information.

        :return: daemon and system specific version information
        :rtype: dict
        """
        return self.request("version")

    def stats(self):
        """Retrieve IKE daemon statistics and load information.

        :return: IKE daemon statistics and load information
        :rtype: dict
        """
        return self.request("stats")

    def reload_settings(self):
        """Reload strongswan.conf settings and any plugins supporting reload.
        """
        self.request("reload-settings")

    def initiate(self, sa):
        """Initiate an SA.

        :param sa: the SA to initiate
        :type sa: dict
        :return: generator for logs emitted as dict
        :rtype: generator
        """
        return self.streamed_request("initiate", "control-log", sa)

    def terminate(self, sa):
        """Terminate an SA.

        :param sa: the SA to terminate
        :type sa: dict
        :return: generator for logs emitted as dict
        :rtype: generator
        """
        return self.streamed_request("terminate", "control-log", sa)

    def redirect(self, sa):
        """Redirect an IKE_SA.

        :param sa: the SA to redirect
        :type sa: dict
        """
        self.request("redirect", sa)

    def install(self, policy):
        """Install a trap, drop or bypass policy defined by a CHILD_SA config.

        :param policy: policy to install
        :type policy: dict
        """
        self.request("install", policy)

    def uninstall(self, policy):
        """Uninstall a trap, drop or bypass policy defined by a CHILD_SA config.

        :param policy: policy to uninstall
        :type policy: dict
        """
        self.request("uninstall", policy)

    def list_sas(self, filters=None):
        """Retrieve active IKE_SAs and associated CHILD_SAs.

        :param filters: retrieve only matching IKE_SAs (optional)
        :type filters: dict
        :return: generator for active IKE_SAs and associated CHILD_SAs as dict
        :rtype: generator
        """
        return self.streamed_request("list-sas", "list-sa", filters)

    def list_policies(self, filters=None):
        """Retrieve installed trap, drop and bypass policies.

        :param filters: retrieve only matching policies (optional)
        :type filters: dict
        :return: generator for installed trap, drop and bypass policies as dict
        :rtype: generator
        """
        return self.streamed_request("list-policies", "list-policy",
                                     filters)

    def list_conns(self, filters=None):
        """Retrieve loaded connections.

        :param filters: retrieve only matching configuration names (optional)
        :type filters: dict
        :return: generator for loaded connections as dict
        :rtype: generator
        """
        return self.streamed_request("list-conns", "list-conn",
                                     filters)

    def get_conns(self):
        """Retrieve connection names loaded exclusively over vici.

        :return: connection names
        :rtype: dict
        """
        return self.request("get-conns")

    def list_certs(self, filters=None):
        """Retrieve loaded certificates.

        :param filters: retrieve only matching certificates (optional)
        :type filters: dict
        :return: generator for loaded certificates as dict
        :rtype: generator
        """
        return self.streamed_request("list-certs", "list-cert", filters)

    def load_conn(self, connection):
        """Load a connection definition into the daemon.

        :param connection: connection definition
        :type connection: dict
        """
        self.request("load-conn", connection)

    def unload_conn(self, name):
        """Unload a connection definition.

        :param name: connection definition name
        :type name: dict
        """
        self.request("unload-conn", name)

    def load_cert(self, certificate):
        """Load a certificate into the daemon.

        :param certificate: PEM or DER encoded certificate
        :type certificate: dict
        """
        self.request("load-cert", certificate)

    def load_key(self, private_key):
        """Load a private key into the daemon.

        :param private_key: PEM or DER encoded key
        """
        self.request("load-key", private_key)

    def load_shared(self, secret):
        """Load a shared IKE PSK, EAP or XAuth secret into the daemon.

        :param secret: shared IKE PSK, EAP or XAuth secret
        :type secret: dict
        """
        self.request("load-shared", secret)

    def flush_certs(self, filter=None):
        """Flush the volatile certificate cache.

        Flush the certificate stored temporarily in the cache. The filter
        allows to flush only a certain type of certificates, e.g. CRLs.

        :param filter: flush only certificates of a given type (optional)
        :type filter: dict
        """
        self.request("flush-certs", filter)

    def clear_creds(self):
        """Clear credentials loaded over vici.

        Clear all loaded certificate, private key and shared key credentials.
        This affects only credentials loaded over vici, but additionally
        flushes the credential cache.
        """
        self.request("clear-creds")

    def load_pool(self, pool):
        """Load a virtual IP pool.

        Load an in-memory virtual IP and configuration attribute pool.
        Existing pools with the same name get updated, if possible.

        :param pool: virtual IP and configuration attribute pool
        :type pool: dict
        """
        return self.request("load-pool", pool)

    def unload_pool(self, pool_name):
        """Unload a virtual IP pool.

        Unload a previously loaded virtual IP and configuration attribute pool.
        Unloading fails for pools with leases currently online.

        :param pool_name: pool by name
        :type pool_name: dict
        """
        self.request("unload-pool", pool_name)

    def get_pools(self, options):
        """Retrieve loaded pools.

        :param options: filter by name and/or retrieve leases (optional)
        :type options: dict
        :return: loaded pools
        :rtype: dict
        """
        return self.request("get-pools", options)
