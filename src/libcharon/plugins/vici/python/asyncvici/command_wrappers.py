class AsyncCommandWrappers:
    async def version(self):
        return await self.request("version")

    async def stats(self):
        return await self.request("stats")

    async def reload_settings(self):
        await self.request("reload-settings")

    async def initiate(self, sa):
        async for x in self.streamed_request("initiate", "control-log", sa):
            yield x

    async def terminate(self, sa):
        async for x in self.streamed_request("terminate", "control-log", sa):
            yield x

    async def rekey(self, sa):
        return await self.request("rekey", sa)

    async def redirect(self, sa):
        return await self.request("redirect", sa)

    async def install(self, policy):
        await self.request("install", policy)

    async def uninstall(self, policy):
        await self.request("uninstall", policy)

    async def list_sas(self, filters=None):
        async for x in self.streamed_request("list-sas", "list-sa", filters):
            yield x

    async def list_policies(self, filters=None):
        async for x in self.streamed_request(
                "list-policies", "list-policy", filters):
            yield x

    async def list_conns(self, filters=None):
        async for x in self.streamed_request(
                "list-conns", "list-conn", filters):
            yield x

    async def get_conns(self):
        return await self.request("get-conns")

    async def list_certs(self, filters=None):
        async for x in self.streamed_request(
                "list-certs", "list-cert", filters):
            yield x

    async def list_authorities(self, filters=None):
        async for x in self.streamed_request(
                "list-authorities", "list-authority", filters):
            yield x

    async def get_authorities(self):
        return await self.request("get-authorities")

    async def load_conn(self, connection):
        await self.request("load-conn", connection)

    async def unload_conn(self, name):
        await self.request("unload-conn", name)

    async def load_cert(self, certificate):
        await self.request("load-cert", certificate)

    async def load_key(self, private_key):
        return await self.request("load-key", private_key)

    async def unload_key(self, key_id):
        await self.request("unload-key", key_id)

    async def get_keys(self):
        return await self.request("get-keys")

    async def load_token(self, token):
        return await self.request("load-token", token)

    async def load_shared(self, secret):
        await self.request("load-shared", secret)

    async def unload_shared(self, identifier):
        await self.request("unload-shared", identifier)

    async def get_shared(self):
        return await self.request("get-shared")

    async def flush_certs(self, filter=None):
        await self.request("flush-certs", filter)

    async def clear_creds(self):
        await self.request("clear-creds")

    async def load_authority(self, ca):
        await self.request("load-authority", ca)

    async def unload_authority(self, ca):
        await self.request("unload-authority", ca)

    async def load_pool(self, pool):
        return await self.request("load-pool", pool)

    async def unload_pool(self, pool_name):
        await self.request("unload-pool", pool_name)

    async def get_pools(self, options=None):
        return await self.request("get-pools", options)

    async def get_algorithms(self):
        return await self.request("get-algorithms")

    async def get_counters(self, options=None):
        return await self.request("get-counters", options)

    async def reset_counters(self, options=None):
        await self.request("reset-counters", options)
